package main

import "testing"

func TestCreate(t *testing.T) {
	t.Run("qwe", func(t *testing.T) {
		a := 1
		b := 2
		c := 3

		if a != 1 || b != 2 || c != 3 {
			t.Fatal("stop")
		}
	})
}
