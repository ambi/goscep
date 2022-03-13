package handler

import (
	"github.com/ambi/goscep/model/scep"

	"github.com/labstack/echo/v4"
)

// GET handles SCEP GET requests.
// RFC8894: 4.1. HTTP POST and GET Message Formats
// GETREQUEST = "GET" SP SCEPPATH "?operation=" OPERATION "&message=" MESSAGE SP HTTP-version CRLF
func (srv *SCEPServer) GET(c echo.Context) error {
	operation := c.QueryParam("operation")
	message := c.QueryParam("message")

	c.Logger().Debugf("SCEP GET request. operation=%s, message=%s", operation, message)

	req := &scep.Request{Operation: operation, Message: []byte(message)}
	return srv.run(c, req)
}
