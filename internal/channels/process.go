package channels

// Process reads each item from input and passes it to action. If filter returns
// an error, it stops and returns that, otherwise it returns nil when input is
// closed.
func Process[T any](input <-chan T, action func(T) error) error {
	for item := range input {
		if err := action(item); err != nil {
			return err
		}
	}
	return nil
}

// Processor wraps Process to simplify errgroup setup
func Processor[T any](input <-chan T, action func(T) error) errGroupFunc {
	return func() error {
		return Process(input, action)
	}
}
