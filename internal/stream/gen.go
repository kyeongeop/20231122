package stream

// GenRecords builds n repeated-object observations for one device. Timestamps
// advance by periodMs plus a fixed clock offset so two devices can share a
// sequence space while disagreeing on wall clock time.
func GenRecords(deviceID uint32, objectID string, n int, startMs, periodMs, clockOffsetMs int64) []Record {
	out := make([]Record, n)
	for i := 0; i < n; i++ {
		out[i] = Record{
			DeviceID: deviceID,
			Seq:      uint64(i + 1),
			TsMillis: startMs + int64(i)*periodMs + clockOffsetMs,
			ObjectID: objectID,
			Metric:   int64(1000 + i),
			Quality:  uint8(10 + (i % 5)),
		}
	}
	return out
}
