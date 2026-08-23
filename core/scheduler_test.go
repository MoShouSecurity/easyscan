package core

import "testing"

func TestResumeQueueFullKeepsTaskPaused(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	scheduler := NewScheduler(store, DefaultScanOptions())
	defer scheduler.Stop()

	paused := &Task{
		ID:        "paused-task",
		Target:    "example.com",
		Type:      TaskDomain,
		Status:    TaskPaused,
		CreatedAt: nowUnix(),
	}
	if err := store.CreateTask(paused); err != nil {
		t.Fatal(err)
	}

	// 不启动 worker，稳定填满队列。
	for i := 0; i < cap(scheduler.queue); i++ {
		if _, err := scheduler.Submit("example.com", TaskDomain, DefaultScanOptions()); err != nil {
			t.Fatalf("fill queue at %d: %v", i, err)
		}
	}
	if err := scheduler.Resume(paused); err == nil {
		t.Fatal("Resume on full queue should fail")
	}
	got, err := store.GetTask(paused.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != TaskPaused {
		t.Fatalf("status after failed resume = %s; want paused", got.Status)
	}
}

func TestPausedPendingTaskIsSkippedByWorker(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	scheduler := NewScheduler(store, DefaultScanOptions())
	defer scheduler.Stop()
	task, err := scheduler.Submit("invalid target that must not run", TaskIP, DefaultScanOptions())
	if err != nil {
		t.Fatal(err)
	}
	paused, err := store.PauseTask(task.ID, "已暂停")
	if err != nil || !paused {
		t.Fatalf("PauseTask paused=%v err=%v", paused, err)
	}
	scheduler.run(task)

	got, err := store.GetTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != TaskPaused {
		t.Fatalf("worker changed paused queued task to %s", got.Status)
	}
}
