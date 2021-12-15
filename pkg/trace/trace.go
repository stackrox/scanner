package trace

import (
	"github.com/sirupsen/logrus"
	"runtime"
)

// Trace here
func Trace() {
	pc := make([]uintptr, 10) // at least 1 entry needed
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line := f.FileLine(pc[0])
	logrus.Infof("%s:%d %s\n", file, line, f.Name())
}
