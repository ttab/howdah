package howdah

import (
	"context"
	"net/http"
	"slices"
)

type Hooks[D any, T any] struct {
	funcs      []HookFunc[T]
	alterFuncs []HookAlterFunc[D, T]
}

type AlterContext[T any] struct {
	Request *http.Request
	Data    T
}

func (h *Hooks[D, T]) RegisterHook(fn HookFunc[T]) {
	h.funcs = append(h.funcs, fn)
}

func (h *Hooks[D, T]) RegisterAlter(fn HookAlterFunc[D, T]) {
	h.alterFuncs = append(h.alterFuncs, fn)
}

func (h *Hooks[D, T]) Collect() []T {
	var list []T

	for _, fn := range h.funcs {
		list = append(list, fn()...)
	}

	return list
}

func (h *Hooks[D, T]) Alter(ctx context.Context, data AlterContext[D], list []T) []T {
	for _, fn := range h.alterFuncs {
		list = fn(ctx, data, list)
	}

	return list
}

type (
	HookFunc[T any]             func() []T
	HookAlterFunc[D any, T any] func(ctx context.Context, data AlterContext[D], list []T) []T
)

type MenuHooks = Hooks[Page, MenuItem]

// SortMenuItems by weight.
func SortMenuItems(menu []MenuItem) {
	slices.SortStableFunc(menu, func(a MenuItem, b MenuItem) int {
		return a.Weight - b.Weight
	})
}
