package howdah

import "github.com/nicksnyder/go-i18n/v2/i18n"

type Link struct {
	Text TextLabel
	HREF string
}

type TextLabel struct {
	Literal     string
	Message     *i18n.Message
	Values      any
	PluralCount *int
}

func TMsg(msg i18n.Message) TextLabel {
	return TextLabel{
		Message: &msg,
	}
}

func TL(str string, forms ...string) TextLabel {
	msg := i18n.Message{
		ID: str,
	}

	switch len(forms) {
	case 0:
		msg.Other = str
	case 1:
		msg.Other = forms[0]
	}

	return TextLabel{
		Message: &msg,
	}
}

func TLiteral(str string) TextLabel {
	return TextLabel{
		Literal: str,
	}
}
