package channels

// Broadcast relays all the messages received on input to outputs. It stops when
// input is closed, and closes outputs at that point. For efficient
// functionality, the outputs should be buffered.
func Broadcast[T any](input <-chan T, outputs ...chan<- T) {
	for _, output := range outputs {
		defer close(output)
	}

	for chunk := range input {
		for _, output := range outputs {
			output <- chunk
		}
	}
}

// Broadcaster wraps Broadcast to simplify errgroup setup
func Broadcaster[T any](input <-chan T, outputs ...chan<- T) errGroupFunc {
	return func() error {
		Broadcast(input, outputs...)
		return nil
	}
}
