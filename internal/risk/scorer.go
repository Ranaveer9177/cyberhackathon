package risk

import "strings"

type FindingInfo struct {
	Severity string
}

type ScoreResult struct {
	Score         int
	Total         int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
}

func CalculateScore(findings []FindingInfo) ScoreResult {
	res := ScoreResult{
		Total: 100,
	}

	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			res.CriticalCount++
		case "HIGH":
			res.HighCount++
		case "MEDIUM":
			res.MediumCount++
		case "LOW":
			res.LowCount++
		case "INFO":
			res.InfoCount++
		}
	}

	deduction := (res.CriticalCount * 15) + (res.HighCount * 8) + (res.MediumCount * 3) + (res.LowCount * 1)
	res.Score = 100 - deduction
	if res.Score < 0 {
		res.Score = 0
	}

	return res
}
