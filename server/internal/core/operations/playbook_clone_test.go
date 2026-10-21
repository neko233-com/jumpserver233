package operations

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCloneWorkflowRunOwnsLoopValues(t *testing.T) {
	source := Run{Items: []Item{{LoopValues: []any{map[string]any{"name": "original", "nested": []any{"kept"}}}}}}
	copy := cloneWorkflowRun(source)
	require.NotSame(t, &source.Items[0].LoopValues[0], &copy.Items[0].LoopValues[0])
	value := copy.Items[0].LoopValues[0].(map[string]any)
	value["name"] = "changed"
	value["nested"].([]any)[0] = "changed"
	require.Equal(t, "original", source.Items[0].LoopValues[0].(map[string]any)["name"])
	require.Equal(t, []any{"kept"}, source.Items[0].LoopValues[0].(map[string]any)["nested"])
	require.Equal(t, cloneWorkflowRun(source), cloneWorkflowRun(source))
	require.Nil(t, cloneWorkflowRun(Run{Items: []Item{{}}}).Items[0].LoopValues)
	require.NotNil(t, cloneWorkflowRun(Run{Items: []Item{{LoopValues: []any{}}}}).Items[0].LoopValues)
}

func TestCloneWorkflowRunConcurrentReaders(t *testing.T) {
	source := Run{Items: []Item{{LoopValues: []any{"original", map[string]any{"nested": []any{"kept"}}}}}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				_ = source.Items[0].LoopValues[0]
				copy := cloneWorkflowRun(source)
				copy.Items[0].LoopValues[0] = "private"
			}
		})
	}
	wg.Wait()
	require.Equal(t, "original", source.Items[0].LoopValues[0])
}
