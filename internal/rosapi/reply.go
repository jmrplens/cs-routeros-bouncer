package routeros

import (
	"strings"

	"github.com/jmrplens/cs-routeros-bouncer/internal/rosapi/proto"
)

// RouterOS reply words. These lived in listen.go upstream; the listen mode is
// pruned here but every reply is still classified by these.
const (
	fatalSentence = "!fatal"
	doneSentence  = "!done"
	trapSentence  = "!trap"
	reSentence    = "!re"
	emptySentence = "!empty"
)

// Reply has all the sentences from a reply.
type Reply struct {
	Re   []*proto.Sentence
	Done *proto.Sentence
}

func (r *Reply) String() string {
	var sb strings.Builder
	for _, sen := range r.Re {
		sb.WriteString(sen.String())
		sb.WriteRune('\n')
	}

	if r.Done != nil {
		sb.WriteString(r.Done.String())
	}

	return sb.String()
}

func (r *Reply) processSentence(sen *proto.Sentence) (bool, error) {
	switch sen.Word {
	case reSentence:
		r.Re = append(r.Re, sen)
	case doneSentence:
		r.Done = sen
		return true, nil
	case trapSentence, fatalSentence:
		return sen.Word == fatalSentence, &DeviceError{sen}
	case "", emptySentence:
		// API docs say that empty sentences should be ignored
	default:
		return true, &UnknownReplyError{sen}
	}
	return false, nil
}
