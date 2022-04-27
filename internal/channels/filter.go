package channels

// Filter reads each item from input and passes it to filter. If filter returns
// an error, it stops and returns that, otherwise it forwards filter's result to
// output. When input ends, output is closed and Filter returns nil.
func Filter[T, U any](
	input <-chan T,
	filter func(T) (U, error),
	output chan<- U,
) error {
	defer close(output)
	for item := range input {
		out, err := filter(item)
		if err != nil {
			return err
		}
		output <- out
	}
	return nil
}

// FilterMany is like Filter, but allows the filter to return many output items
// for each input item.
func FilterMany[T, U any](
	input <-chan T,
	filter func(T) ([]U, error),
	output chan<- U,
) error {
	defer close(output)
	for item := range input {
		out, err := filter(item)
		if err != nil {
			return err
		}
		for _, o := range out {
			output <- o
		}
	}
	return nil
}

// Filterer wraps Filter for easy errgroup setup
func Filterer[T, U any](
	input <-chan T,
	filter func(T) (U, error),
	output chan<- U,
) errGroupFunc {
	return func() error {
		return Filter(input, filter, output)
	}
}

// FiltererMany wraps FilterMany for easy errgroup setup
func FiltererMany[T, U any](
	input <-chan T,
	filter func(T) ([]U, error),
	output chan<- U,
) errGroupFunc {
	return func() error {
		return FilterMany(input, filter, output)
	}
}
