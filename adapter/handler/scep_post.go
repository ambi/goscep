package handler

import (
	"io/ioutil"

	"github.com/ambi/goscep/model/scep"

	"github.com/labstack/echo/v4"
)

// POST handles SCEP POST requests.
// RFC8894: 4.1. HTTP POST and GET Message Formats
// POSTREQUEST = "POST" SP SCEPPATH "?operation=" OPERATION SP HTTP-version CRLF
func (srv *SCEPServer) POST(c echo.Context) error {
	operation := c.QueryParam("operation")
	var message []byte
	var err error
	if body := c.Request().Body; body != nil {
		defer body.Close()

		// Limiting request body size is NOT our responsibility. It should be archived by web servers.
		message, err = ioutil.ReadAll(body)
		if err != nil {
			c.Logger().Errorf("error in reading request body. error=%s", err.Error())

			return srv.systemError(c)
		}
	}

	c.Logger().Debugf("SCEP POST request. operation=%s, message=%s", operation, message)

	req := &scep.Request{Operation: operation, Message: message}
	return srv.run(c, req)
}
