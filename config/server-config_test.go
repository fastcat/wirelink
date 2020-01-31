package config

import "testing"

import "github.com/stretchr/testify/assert"

import "fmt"

import "math/rand"

func TestServer_ShouldReportIface(t *testing.T) {
	ifName := func(prefix string) string {
		return fmt.Sprintf("%s%d", prefix, rand.Int31())
	}
	self := ifName("wg")
	matchEth := []string{"eth*"}

	type fields struct {
		Iface        string
		ReportIfaces []string
		HideIfaces   []string
	}
	type args struct {
		name string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{"self", fields{Iface: self}, args{self}, false},
		{"self included", fields{Iface: self, ReportIfaces: []string{self}}, args{self}, false},
		{"default", fields{Iface: self}, args{ifName("eth")}, true},
		{"included", fields{Iface: self, ReportIfaces: matchEth}, args{ifName("eth")}, true},
		{"excluded", fields{Iface: self, HideIfaces: matchEth}, args{ifName("eth")}, false},
		{"exclude priority", fields{Iface: self, ReportIfaces: matchEth, HideIfaces: matchEth}, args{ifName("eth")}, false},
		{"not included", fields{Iface: self, ReportIfaces: matchEth}, args{ifName("wl")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				Iface:        tt.fields.Iface,
				ReportIfaces: tt.fields.ReportIfaces,
				HideIfaces:   tt.fields.HideIfaces,
			}
			got := s.ShouldReportIface(tt.args.name)
			assert.Equal(t, tt.want, got)
		})
	}
}
