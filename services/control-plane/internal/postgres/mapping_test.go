package postgres

import (
	"fmt"
	"reflect"
)

type valuesRow []any

func (r valuesRow) Scan(destinations ...any) error {
	if len(destinations) != len(r) {
		return fmt.Errorf("got %d destinations, want %d", len(destinations), len(r))
	}
	for i, value := range r {
		destination := reflect.ValueOf(destinations[i])
		if destination.Kind() != reflect.Pointer || destination.IsNil() {
			return fmt.Errorf("destination %d is not a pointer", i)
		}
		target := destination.Elem()
		if value == nil {
			target.SetZero()
			continue
		}
		source := reflect.ValueOf(value)
		if !source.Type().AssignableTo(target.Type()) {
			return fmt.Errorf("value %d has type %s, want %s", i, source.Type(), target.Type())
		}
		target.Set(source)
	}
	return nil
}
