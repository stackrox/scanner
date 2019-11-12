package nvd

// SingletonAppender returns the instance of the NVD appender.
func SingletonAppender() Appender {
	return &appender{}
}
