package server

import (
	"reflect"
	"sync"
	"testing"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/internal/testutils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_peerConfigSet_Clone(t *testing.T) {
	k1 := testutils.MustKey(t)

	type fields struct {
		peerStates map[wgtypes.Key]*apply.PeerConfigState
	}
	tests := []struct {
		name   string
		fields *fields
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&fields{map[wgtypes.Key]*apply.PeerConfigState{}},
		},
		{
			"filled",
			&fields{map[wgtypes.Key]*apply.PeerConfigState{
				k1: (*apply.PeerConfigState)(nil).EnsureNotNil(),
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pcs *peerConfigSet
			if tt.fields != nil {
				pcs = &peerConfigSet{
					peerStates: tt.fields.peerStates,
					psm:        &sync.Mutex{},
				}
			}
			got := pcs.Clone()
			if tt.fields == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.fields.peerStates, got.peerStates)
			assert.NotNil(t, got.psm)
			// make sure it really is different
			assert.False(t, pcs.psm == got.psm)
			// can't do == checks on maps
			assert.NotEqual(t, reflect.ValueOf(pcs.peerStates).Pointer(), reflect.ValueOf(got.peerStates).Pointer())
			// if we get here, we already know the map keys are equal
			for k := range tt.fields.peerStates {
				assert.False(t, pcs.peerStates[k] == got.peerStates[k])
				// inner portion of PCS is a separate test
			}
		})
	}
}
