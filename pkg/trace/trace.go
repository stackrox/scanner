package trace

import (
	"runtime"

	"github.com/sirupsen/logrus"
)

// Trace here
func Trace() {
	pc := make([]uintptr, 12) // at least 1 entry needed
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	file, line := f.FileLine(pc[0])
	logrus.Infof("%s:%d %s\n", file, line, f.Name())
	f = runtime.FuncForPC(pc[1])
	file, line = f.FileLine(pc[1])
	logrus.Infof("caller %s:%d %s\n", file, line, f.Name())
	f = runtime.FuncForPC(pc[2])
	file, line = f.FileLine(pc[2])
	logrus.Infof("caller caller %s:%d %s\n", file, line, f.Name())
}
