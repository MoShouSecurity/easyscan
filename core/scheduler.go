package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Scheduler 进程内任务调度器：提交侦察任务，由 worker 池异步执行并落库。
type Scheduler struct {
	store  *Store
	opts   ScanOptions
	queue  chan *Task
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	tasks  map[string]context.CancelFunc // taskID -> cancel，支持单任务暂停
}

// NewScheduler 构造调度器。workers 为并发 worker 数。
func NewScheduler(store *Store, opts ScanOptions, workers int) *Scheduler {
	if workers <= 0 {
		workers = 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		store:  store,
		opts:   opts,
		queue:  make(chan *Task, 256),
		ctx:    ctx,
		cancel: cancel,
		wg:     sync.WaitGroup{},
		tasks:  make(map[string]context.CancelFunc),
	}
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
	params, _ := json.Marshal(opts)
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
	s.queue <- t
	return t, nil
}

// Resume 重新入队执行任务（用于恢复暂停的任务）。
func (s *Scheduler) Resume(t *Task) {
	s.queue <- t
}

// CancelTask 取消指定任务（暂停用）。
func (s *Scheduler) CancelTask(taskID string) {
	s.mu.Lock()
	cancel := s.tasks[taskID]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Scheduler) worker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case t := <-s.queue:
			s.run(t)
		}
	}
}

func (s *Scheduler) run(t *Task) {
	// 引擎内任何 panic（如第三方库）都不应带崩整个 GUI 进程：捕获后把任务标记为失败。
	defer func() {
		if r := recover(); r != nil {
			t.Status = TaskFailed
			t.FinishedAt = nowUnix()
			t.Message = fmt.Sprintf("任务异常终止: %v", r)
			_ = s.store.UpdateTask(t)
		}
	}()

	var opts ScanOptions
	_ = json.Unmarshal([]byte(t.Params), &opts)
	if opts.Concurrency == 0 {
		opts = s.opts
	}

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

	engine := NewEngine(s.store, opts)
	update := func(status TaskStatus, progress int, msg string) {
		t.Status = status
		t.Progress = progress
		t.Message = msg
		if status == TaskFinished || status == TaskFailed {
			t.FinishedAt = nowUnix()
		}
		_ = s.store.UpdateTask(t)
	}

	update(TaskRunning, 0, "任务启动")

	err := engine.ScanTarget(ctx, t.Target, t.Type, t.ID, t.Stage, func(stage, detail string, progress int) {
		update(TaskRunning, progress, stage+": "+detail)
	})

	if err != nil {
		if ctx.Err() != nil {
			return // 被暂停取消，状态由 PauseTask 处理
		}
		update(TaskFailed, 100, err.Error())
		return
	}
	update(TaskFinished, 100, "完成")
}
