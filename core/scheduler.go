package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Scheduler 进程内任务调度器：提交侦察任务，由 worker 池异步执行并落库。
type Scheduler struct {
	store     *Store
	opts      ScanOptions
	queue     chan *Task
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
	enqueueMu sync.Mutex                    // 串行化入队与容量检查，保证状态变更后一定能入队
	tasks     map[string]context.CancelFunc // taskID -> cancel，支持单任务暂停
	secrets   map[string]taskSecrets        // 仅内存保存新任务凭据，绝不写入 SQLite
}

type taskSecrets struct {
	fofaKey  string
	proxyURL string
}

// NewScheduler 构造调度器；调用 Start 指定 worker 数后开始消费任务。
func NewScheduler(store *Store, opts ScanOptions) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		store:   store,
		opts:    opts,
		queue:   make(chan *Task, 256),
		ctx:     ctx,
		cancel:  cancel,
		wg:      sync.WaitGroup{},
		tasks:   make(map[string]context.CancelFunc),
		secrets: make(map[string]taskSecrets),
	}
}

// UpdateOptions 更新恢复任务使用的当前运行时配置（尤其是不会持久化的凭据）。
func (s *Scheduler) UpdateOptions(opts ScanOptions) {
	s.mu.Lock()
	s.opts = opts
	s.mu.Unlock()
}

// Start 启动 worker 池。
func (s *Scheduler) Start(workers int) {
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
}

// Stop 停止调度器并等待 worker 退出。
func (s *Scheduler) Stop() {
	s.cancel()
	s.wg.Wait()
}

// Submit 创建并提交一个任务，返回任务记录（状态为 pending）。
func (s *Scheduler) Submit(target string, typ TaskType, opts ScanOptions) (*Task, error) {
	persisted := opts
	persisted.FofaKey = ""
	persisted.ProxyURL = ""
	params, err := json.Marshal(persisted)
	if err != nil {
		return nil, fmt.Errorf("序列化扫描参数: %w", err)
	}
	t := &Task{
		ID:        newID(),
		Target:    target,
		Type:      typ,
		Status:    TaskPending,
		Params:    string(params),
		CreatedAt: nowUnix(),
	}
	if err := s.store.CreateTask(t); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.secrets[t.ID] = taskSecrets{fofaKey: opts.FofaKey, proxyURL: opts.ProxyURL}
	s.mu.Unlock()

	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	if s.ctx.Err() != nil {
		s.forgetSecrets(t.ID)
		t.Status = TaskFailed
		t.Message = "调度器已停止"
		t.FinishedAt = nowUnix()
		_ = s.store.UpdateTask(t)
		return nil, fmt.Errorf("调度器已停止")
	}
	// 所有发送方都持有 enqueueMu；worker 只会腾出容量，因此检查后发送不会阻塞。
	if len(s.queue) >= cap(s.queue) {
		s.forgetSecrets(t.ID)
		t.Status = TaskFailed
		t.Message = "任务队列已满，请稍后重试"
		t.FinishedAt = nowUnix()
		_ = s.store.UpdateTask(t)
		return nil, fmt.Errorf("任务队列已满，请稍后重试")
	}
	s.queue <- t
	return t, nil
}

// Resume 原子地把暂停任务改为 pending 并重新入队。队列满时不改变原状态。
func (s *Scheduler) Resume(t *Task) error {
	s.enqueueMu.Lock()
	defer s.enqueueMu.Unlock()
	if s.ctx.Err() != nil {
		return fmt.Errorf("调度器已停止")
	}
	if len(s.queue) >= cap(s.queue) {
		return fmt.Errorf("任务队列已满，请稍后重试")
	}
	queued, err := s.store.QueuePausedTask(t.ID, "恢复中")
	if err != nil {
		return err
	}
	if !queued {
		return fmt.Errorf("任务不在暂停状态")
	}
	t.Status = TaskPending
	t.Message = "恢复中"
	s.queue <- t
	return nil
}

// CancelTask 取消指定的运行中任务，返回任务是否正在 worker 中执行。
func (s *Scheduler) CancelTask(taskID string) bool {
	s.mu.Lock()
	cancel := s.tasks[taskID]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		return true
	}
	return false
}

// IsTaskActive 返回任务是否仍在 worker 中执行（取消后到完全退出之间也为 true）。
func (s *Scheduler) IsTaskActive(taskID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.tasks[taskID]
	return ok
}

func (s *Scheduler) worker() {
	defer s.wg.Done()
	for {
		// 优先响应整体关闭，避免取消后仍随机取出大量排队任务。
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		select {
		case <-s.ctx.Done():
			return
		case t := <-s.queue:
			s.run(t)
		}
	}
}

func (s *Scheduler) run(t *Task) {
	s.mu.Lock()
	secrets, hasTaskSecrets := s.secrets[t.ID]
	delete(s.secrets, t.ID)
	defaultOpts := s.opts
	s.mu.Unlock()
	if !hasTaskSecrets {
		secrets = taskSecrets{fofaKey: defaultOpts.FofaKey, proxyURL: defaultOpts.ProxyURL}
	}

	var opts ScanOptions
	if err := json.Unmarshal([]byte(t.Params), &opts); err != nil {
		t.Status = TaskFailed
		t.FinishedAt = nowUnix()
		t.Message = "解析任务参数失败: " + err.Error()
		_, _ = s.store.UpdateTaskIfStatus(t, TaskPending)
		return
	}
	if opts.Concurrency == 0 {
		opts = defaultOpts
	}
	// 即便旧任务 params 中含凭据，也始终覆盖为内存中的当前值，防止旧 key 复活。
	opts.FofaKey = secrets.fofaKey
	opts.ProxyURL = secrets.proxyURL

	// 每个任务独立 context，支持单独取消（暂停）。
	ctx, cancel := context.WithCancel(s.ctx)
	s.mu.Lock()
	s.tasks[t.ID] = cancel
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.tasks, t.ID)
		s.mu.Unlock()
		cancel()
	}()
	// 引擎内任何 panic（如第三方库）都不应带崩整个 GUI 进程：捕获后把任务标记为失败。
	defer func() {
		if r := recover(); r != nil {
			t.Status = TaskFailed
			t.FinishedAt = nowUnix()
			t.Message = recoveredPanicError("任务调度器", r).Error()
			_, _ = s.store.UpdateTaskIfStatus(t, TaskRunning)
		}
	}()

	engine := NewEngine(s.store, opts)
	updateRunning := func(status TaskStatus, progress int, msg string) bool {
		t.Status = status
		t.Progress = progress
		t.Message = msg
		if status == TaskFinished || status == TaskFailed {
			t.FinishedAt = nowUnix()
		}
		updated, _ := s.store.UpdateTaskIfStatus(t, TaskRunning)
		return updated
	}

	t.Status = TaskRunning
	t.Message = "任务启动"
	started, err := s.store.UpdateTaskIfStatus(t, TaskPending)
	if err != nil || !started {
		return // 已暂停或删除的排队任务不再执行
	}

	err = engine.ScanTarget(ctx, t.Target, t.Type, t.ID, t.Stage, func(stage, detail string, progress int) {
		if ctx.Err() == nil {
			updateRunning(TaskRunning, progress, stage+": "+detail)
		}
	})

	// 即使某个模块吞掉了 context 错误，也不能把已暂停任务误标为完成。
	if ctx.Err() != nil {
		if s.ctx.Err() != nil {
			updateRunning(TaskPaused, t.Progress, "程序关闭，任务已暂停")
		}
		return
	}
	if err != nil {
		updateRunning(TaskFailed, 100, err.Error())
		return
	}
	updateRunning(TaskFinished, 100, "完成")
}

func (s *Scheduler) forgetSecrets(taskID string) {
	s.mu.Lock()
	delete(s.secrets, taskID)
	s.mu.Unlock()
}
