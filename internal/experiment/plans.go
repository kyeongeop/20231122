package experiment

import "cacheleak.local/experiment/internal/model"

const (
	opaquePath  = "/static/opaque.q7x"
	tailPath    = "/static/tail.q7x"
	partialPath = "/static/partial.q7x"
)

func NewPlans() []model.ScenarioPlan {
	return []model.ScenarioPlan{
		{
			Name:       "order-forward",
			Order:      "v1-then-v2",
			ResetCache: true,
			Requests: []model.RequestSpec{
				request(opaquePath, "snap-v1", 1, 0, "fresh-v1"),
				request(opaquePath, "snap-v2", 1, 0, "stale-v1-leak"),
				request(opaquePath, "snap-v2", 2, 2, "same-stale-v1"),
				request(opaquePath, "snap-v2", 3, 2, "same-stale-v1"),
			},
		},
		{
			Name:       "order-reverse",
			Order:      "v2-then-v1",
			ResetCache: true,
			Requests: []model.RequestSpec{
				request(opaquePath, "snap-v2", 1, 0, "fresh-v2"),
				request(opaquePath, "snap-v1", 1, 0, "stale-v2-leak"),
				request(opaquePath, "snap-v1", 2, 2, "same-stale-v2"),
				request(opaquePath, "snap-v1", 3, 2, "same-stale-v2"),
			},
		},
		{
			Name:       "repeat-forward-a",
			Order:      "v1-then-v2",
			ResetCache: true,
			Requests: []model.RequestSpec{
				request(opaquePath, "snap-v1", 1, 0, "fresh-v1"),
				request(opaquePath, "snap-v2", 1, 0, "stale-v1-leak"),
				request(opaquePath, "snap-v2", 2, 2, "same-stale-v1"),
			},
		},
		{
			Name:       "repeat-forward-b",
			Order:      "v1-then-v2",
			ResetCache: true,
			Requests: []model.RequestSpec{
				request(opaquePath, "snap-v1", 1, 0, "fresh-v1"),
				request(opaquePath, "snap-v2", 1, 0, "stale-v1-leak"),
				request(opaquePath, "snap-v2", 2, 2, "same-stale-v1"),
			},
		},
		{
			Name:       "error-continuation",
			Order:      "v1-v2-error-tail",
			ResetCache: true,
			Requests: []model.RequestSpec{
				request(opaquePath, "snap-v1", 1, 0, "fresh-v1"),
				request(opaquePath, "snap-v2", 1, 0, "stale-v1-leak"),
				request(partialPath, "snap-v2", 1, 0, "isolated-404"),
				request(tailPath, "snap-v1", 1, 0, "fresh-tail-v1"),
				request(tailPath, "snap-v2", 1, 0, "stale-tail-v1"),
				request(tailPath, "snap-v2", 2, 3, "same-stale-tail-v1"),
			},
		},
	}
}

func request(logicalPath, snapshotID string, submit, repeatOf int, expect string) model.RequestSpec {
	return model.RequestSpec{
		ObjectKey:  snapshotID + ":" + logicalPath,
		Method:     "GET",
		Path:       logicalPath,
		SnapshotID: snapshotID,
		Submit:     submit,
		RepeatOf:   repeatOf,
		Expect:     expect,
	}
}
