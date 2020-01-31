package trust

import (
	"fmt"
	"net"
	"testing"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockEvaluator struct {
	MockEvaluator
}

func newEvaluator(t *testing.T) *mockEvaluator {
	m := &mockEvaluator{}
	m.Test(t)
	return m
}

func asEvaluators(mocks ...*mockEvaluator) []Evaluator {
	ret := make([]Evaluator, len(mocks))
	for i, m := range mocks {
		ret[i] = m
	}
	return ret
}

func asAny(mocks ...*mockEvaluator) []interface{} {
	ret := make([]interface{}, len(mocks))
	for i, m := range mocks {
		ret[i] = m
	}
	return ret
}

func (m *mockEvaluator) knows(key wgtypes.Key) *mockEvaluator {
	m.On("IsKnown", &fact.PeerSubject{Key: key}).Return(true)
	return m
}
func (m *mockEvaluator) knowsNot(key wgtypes.Key) *mockEvaluator {
	m.On("IsKnown", &fact.PeerSubject{Key: key}).Return(false)
	return m
}
func ipMatcher(ip net.IP) func(source net.UDPAddr) bool {
	return func(source net.UDPAddr) bool {
		return ip.Equal(source.IP)
	}
}
func (m *mockEvaluator) trustsSource(ip net.IP, level Level) *mockEvaluator {
	m.On("TrustLevel", mock.Anything, mock.MatchedBy(ipMatcher(ip))).Return(&level)
	return m
}
func (m *mockEvaluator) knowsSource(ip net.IP, level *Level) *mockEvaluator {
	m.On("TrustLevel", mock.Anything, mock.MatchedBy(ipMatcher(ip))).Return(level)
	return m
}
func (m *mockEvaluator) ignoresSource(ip net.IP) *mockEvaluator {
	m.On("TrustLevel", mock.Anything, mock.MatchedBy(ipMatcher(ip))).Return(nil)
	return m
}

func trustPtr(level Level) *Level {
	return &level
}

func Test_composite_IsKnown(t *testing.T) {
	k := testutils.MustKey(t)
	subject := &fact.PeerSubject{Key: k}

	type fields struct {
		mode  CompositeMode
		inner []*mockEvaluator
	}
	type args struct {
		subject fact.Subject
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			"empty",
			fields{},
			args{subject},
			false,
		},
		{
			"one inner unknown",
			fields{inner: []*mockEvaluator{newEvaluator(t).knowsNot(k)}},
			args{subject},
			false,
		},
		{
			"one inner known",
			fields{inner: []*mockEvaluator{newEvaluator(t).knows(k)}},
			args{subject},
			true,
		},
		{
			"two inner one known",
			fields{inner: []*mockEvaluator{
				newEvaluator(t).knowsNot(k),
				newEvaluator(t).knows(k),
			}},
			args{subject},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, m := range tt.fields.inner {
				m.Test(t)
			}
			c := &composite{
				mode:  tt.fields.mode,
				inner: asEvaluators(tt.fields.inner...),
			}
			got := c.IsKnown(tt.args.subject)
			mock.AssertExpectationsForObjects(t, asAny(tt.fields.inner...)...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_composite_TrustLevel(t *testing.T) {
	// k := testutils.MustKey(t)
	// subject := &fact.PeerSubject{Key: k}
	source := testutils.RandUDP4Addr(t)

	type fields struct {
		mode  CompositeMode
		inner []*mockEvaluator
	}
	type args struct {
		fact   *fact.Fact
		source net.UDPAddr
	}
	type test struct {
		name    string
		fields  fields
		args    args
		wantRet *Level
	}

	fancyPattern := func(name string, mode CompositeMode, e1, e2, want *Level, call1, call2 bool) test {
		mocks := []*mockEvaluator{
			newEvaluator(t),
			newEvaluator(t),
		}
		if call1 {
			mocks[0].knowsSource(source.IP, e1)
		}
		if call2 {
			mocks[1].knowsSource(source.IP, e2)
		}
		return test{
			fmt.Sprintf("%s (%v, %v,%v) => %v", name, mode, e1, e2, want),
			fields{mode, mocks},
			args{nil, *source},
			want,
		}
	}

	pattern := func(name string, mode CompositeMode, e1, e2, want *Level) test {
		return fancyPattern(name, mode, e1, e2, want, true, true)
	}

	tests := []test{
		pattern("nobody knows", FirstOnly, nil, nil, nil),
		pattern("nobody knows", LeastPermission, nil, nil, nil),
		pattern("nobody knows", MostPermission, nil, nil, nil),

		fancyPattern("first knows", FirstOnly, trustPtr(AddPeer), trustPtr(SetTrust), trustPtr(AddPeer), true, false),
		pattern("first knows", LeastPermission, trustPtr(AddPeer), trustPtr(SetTrust), trustPtr(AddPeer)),
		pattern("first knows", MostPermission, trustPtr(AddPeer), trustPtr(SetTrust), trustPtr(SetTrust)),

		// nil shouldn't count as "first"
		pattern("second knows", FirstOnly, nil, trustPtr(AddPeer), trustPtr(AddPeer)),
		pattern("second knows", LeastPermission, nil, trustPtr(AddPeer), trustPtr(AddPeer)),
		pattern("second knows", MostPermission, nil, trustPtr(AddPeer), trustPtr(AddPeer)),

		fancyPattern("varying levels", FirstOnly, trustPtr(Untrusted), trustPtr(SetTrust), trustPtr(Untrusted), true, false),
		pattern("varying levels", LeastPermission, trustPtr(Untrusted), trustPtr(SetTrust), trustPtr(Untrusted)),
		pattern("varying levels", MostPermission, trustPtr(Untrusted), trustPtr(SetTrust), trustPtr(SetTrust)),

		pattern("decreasing levels", LeastPermission, trustPtr(SetTrust), trustPtr(Untrusted), trustPtr(Untrusted)),
		pattern("decreasing levels", MostPermission, trustPtr(SetTrust), trustPtr(Untrusted), trustPtr(SetTrust)),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, m := range tt.fields.inner {
				m.Test(t)
			}
			c := CreateComposite(tt.fields.mode, asEvaluators(tt.fields.inner...)...)
			gotRet := c.TrustLevel(tt.args.fact, tt.args.source)
			mock.AssertExpectationsForObjects(t, asAny(tt.fields.inner...)...)
			if tt.wantRet == nil {
				assert.Nil(t, gotRet)
			} else {
				require.NotNil(t, gotRet)
				assert.Equal(t, *tt.wantRet, *gotRet, "expect %s got %s", tt.wantRet.String(), gotRet.String())
			}
		})
	}
}
