package martian_jwt

import (
	"encoding/json"
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/martian"
	"github.com/google/martian/parse"
	"github.com/gorilla/context"
)

func init() {
	parse.Register("jwt.TrampolimModifier", trampolimModifierFromJSON)
}


type TrampolimModifier struct {
	privateKey string
}

type TrampolimModifierJSON struct {
	PrivateKey  string  `json:"privateKey"`
	Scope   []parse.ModifierType `json:"scope"`
}

func (m *TrampolimModifier) ModifyRequest(req *http.Request) error {
	tokenJWT := req.Header.Get("Authorization")
	//if tokenJWT == "" {
	//	http.Error()
	//}

	token, err := jwt.Parse(tokenJWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, nil
		}
		return nil, nil
	})
	if err != nil {
		//http.Error()
		return nil
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userId := claims["user_id"].(string)
		context.Set(req, "user_id", userId)
		log.Printf("Authenticated User: %s\n", userId)
	} else {
		//http.Error()
		return nil
	}

	return nil
}

func TrampolimNewModifier(privateKey string) martian.RequestModifier {
	return &TrampolimModifier{
		privateKey: privateKey,
	}
}


func trampolimModifierFromJSON(b []byte) (*parse.Result, error) {
	msg := &TrampolimModifierJSON{}

	if err := json.Unmarshal(b, msg); err != nil {
		return nil, err
	}

	return parse.NewResult(TrampolimNewModifier(msg.PrivateKey), msg.Scope)
}