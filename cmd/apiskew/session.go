package main

import (
	"context"
	"errors"
	"fmt"

	"apiskew.local/apiskew/internal/domain"
	"apiskew.local/apiskew/internal/store"
)

type sessionView struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	ObjectKey      string `json:"object_key"`
	ObjectID       string `json:"object_canonical_id"`
	ScenarioSHA256 string `json:"scenario_sha256"`
	Samples        int    `json:"samples"`
	Runs           int    `json:"runs"`
}

func (c *cli) init(ctx context.Context, args []string) error {
	flags := newFlagSet("init", c.stderr)
	name := flags.String("name", "", "session name")
	configPath := flags.String("config", "", "scenario JSON file")
	sessionID := flags.String("id", "", "explicit session id")
	objectKey := flags.String("object-key", "", "override duplicate object key")
	canonicalID := flags.String("canonical-id", "", "override duplicate object canonical id")
	jsonOut := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("init does not accept positional arguments")
	}
	var scenario domain.Scenario
	var err error
	if *configPath == "" {
		scenario = domain.DefaultScenario()
	} else {
		scenario, err = domain.LoadScenario(*configPath)
		if err != nil {
			return err
		}
	}
	if *objectKey != "" {
		scenario.Object.Key = *objectKey
	}
	if *canonicalID != "" {
		scenario.Object.CanonicalID = *canonicalID
	}
	if err := scenario.Validate(); err != nil {
		return err
	}
	st, err := c.openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	session, err := st.CreateSession(ctx, *sessionID, *name, scenario)
	if err != nil {
		return err
	}
	_ = st.AddEvent(ctx, session.ID, "", "session_created", struct {
		ObjectKey      string `json:"object_key"`
		ObjectID       string `json:"object_canonical_id"`
		ScenarioSHA256 string `json:"scenario_sha256"`
	}{session.Scenario.Object.Key, session.Scenario.Object.CanonicalID, session.ScenarioSHA})
	if *jsonOut {
		return emitJSON(c.stdout, sessionView{
			ID:             session.ID,
			Name:           session.Name,
			Status:         session.Status,
			ObjectKey:      session.Scenario.Object.Key,
			ObjectID:       session.Scenario.Object.CanonicalID,
			ScenarioSHA256: session.ScenarioSHA,
		})
	}
	fmt.Fprintf(c.stdout, "session %s created\n", session.ID)
	fmt.Fprintf(c.stdout, "object: %s (%s)\n", session.Scenario.Object.Key, session.Scenario.Object.CanonicalID)
	fmt.Fprintf(c.stdout, "scenario: %s\n", session.ScenarioSHA)
	fmt.Fprintf(c.stdout, "database: %s\n", c.dbPath)
	return nil
}

func (c *cli) list(ctx context.Context, args []string) error {
	flags := newFlagSet("list", c.stderr)
	jsonOut := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	st, err := c.openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	sessions, err := st.ListSessions(ctx)
	if err != nil {
		return err
	}
	views := make([]sessionView, 0, len(sessions))
	for _, session := range sessions {
		counts, err := st.Counts(ctx, session.ID)
		if err != nil {
			return err
		}
		views = append(views, sessionView{
			ID:             session.ID,
			Name:           session.Name,
			Status:         session.Status,
			ObjectKey:      session.Scenario.Object.Key,
			ObjectID:       session.Scenario.Object.CanonicalID,
			ScenarioSHA256: session.ScenarioSHA,
			Samples:        counts.Samples,
			Runs:           counts.Runs,
		})
	}
	if *jsonOut {
		return emitJSON(c.stdout, views)
	}
	if len(views) == 0 {
		fmt.Fprintln(c.stdout, "no sessions")
		return nil
	}
	for _, view := range views {
		fmt.Fprintf(c.stdout, "%s  %-8s  samples=%d runs=%d  %s  %s\n",
			view.ID, view.Status, view.Samples, view.Runs, view.ObjectKey, view.Name)
	}
	return nil
}

type sampleStatus struct {
	ID             string `json:"id"`
	Ordinal        int    `json:"ordinal"`
	Source         string `json:"source"`
	Status         string `json:"status"`
	SampleSHA256   string `json:"sample_sha256"`
	LatestAttempt  int    `json:"latest_attempt"`
	V1Allow        bool   `json:"v1_allow"`
	V2Allow        bool   `json:"v2_allow"`
	PermissionDiff bool   `json:"permission_difference"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type statusView struct {
	Session sessionView    `json:"session"`
	Samples []sampleStatus `json:"samples"`
	Events  []store.Event  `json:"events"`
}

func (c *cli) status(ctx context.Context, args []string) error {
	flags := newFlagSet("status", c.stderr)
	sessionID := flags.String("session", "", "session id (default: latest)")
	jsonOut := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	st, err := c.openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	id, err := c.sessionID(ctx, st, *sessionID)
	if err != nil {
		return err
	}
	session, err := st.GetSession(ctx, id)
	if err != nil {
		return err
	}
	counts, err := st.Counts(ctx, id)
	if err != nil {
		return err
	}
	samples, err := st.ListSamples(ctx, id)
	if err != nil {
		return err
	}
	events, err := st.ListEvents(ctx, id)
	if err != nil {
		return err
	}
	if len(events) > 20 {
		events = events[len(events)-20:]
	}
	sampleViews := make([]sampleStatus, 0, len(samples))
	for _, sample := range samples {
		view := sampleStatus{
			ID:           sample.ID,
			Ordinal:      sample.Ordinal,
			Source:       sample.Source,
			Status:       sample.Status,
			SampleSHA256: sample.InputSHA256,
		}
		if run, err := st.LatestRun(ctx, id, sample.ID); err == nil {
			view.LatestAttempt = run.Attempt
			view.V1Allow = run.V1Allow
			view.V2Allow = run.V2Allow
			view.PermissionDiff = run.PermissionDifference
			view.EvidenceSHA256 = run.EvidenceSHA256
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		sampleViews = append(sampleViews, view)
	}
	view := statusView{
		Session: sessionView{
			ID:             session.ID,
			Name:           session.Name,
			Status:         session.Status,
			ObjectKey:      session.Scenario.Object.Key,
			ObjectID:       session.Scenario.Object.CanonicalID,
			ScenarioSHA256: session.ScenarioSHA,
			Samples:        counts.Samples,
			Runs:           counts.Runs,
		},
		Samples: sampleViews,
		Events:  events,
	}
	if *jsonOut {
		return emitJSON(c.stdout, view)
	}
	fmt.Fprintf(c.stdout, "session  %s  %s  (%s)\n", session.ID, session.Status, session.Name)
	fmt.Fprintf(c.stdout, "object   %s (%s)\n", session.Scenario.Object.Key, session.Scenario.Object.CanonicalID)
	fmt.Fprintf(c.stdout, "counts   samples=%d runs=%d\n", counts.Samples, counts.Runs)
	for _, sample := range sampleViews {
		fmt.Fprintf(c.stdout, "%s  ord=%-4d  v1=%-5t v2=%-5t diff=%-5t attempt=%-4d  %s\n",
			sample.ID, sample.Ordinal, sample.V1Allow, sample.V2Allow,
			sample.PermissionDiff, sample.LatestAttempt, sample.SampleSHA256[:12])
	}
	if len(events) > 0 {
		last := events[len(events)-1]
		fmt.Fprintf(c.stdout, "last event  id=%d kind=%s at=%s\n", last.ID, last.Kind, last.CreatedAt)
	}
	return nil
}

func (c *cli) setStatus(ctx context.Context, args []string, status string) error {
	flags := newFlagSet(status, c.stderr)
	sessionID := flags.String("session", "", "session id (default: latest)")
	jsonOut := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	st, err := c.openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	id, err := c.sessionID(ctx, st, *sessionID)
	if err != nil {
		return err
	}
	if err := st.SetSessionStatus(ctx, id, status); err != nil {
		return err
	}
	_ = st.AddEvent(ctx, id, "", "session_status_changed", struct {
		Status string `json:"status"`
	}{status})
	if *jsonOut {
		return emitJSON(c.stdout, map[string]string{"session_id": id, "status": status})
	}
	fmt.Fprintf(c.stdout, "session %s status=%s\n", id, status)
	return nil
}
