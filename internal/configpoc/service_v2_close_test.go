package configpoc

import (
	"sync"
	"testing"
)

func TestServiceV2CloseUninitialized(t *testing.T) {
	for name, service := range map[string]*ServiceV2{
		"nil":           nil,
		"zero":          {},
		"missing-store": {coordinator: &v2Coordinator{}},
	} {
		t.Run(name, func(t *testing.T) {
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := service.Close(); err != nil {
						t.Errorf("close: %v", err)
					}
				}()
			}
			wg.Wait()
			if err := service.Close(); err != nil {
				t.Fatalf("repeated close: %v", err)
			}
		})
	}
}
