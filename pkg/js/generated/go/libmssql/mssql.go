package mssql

import (
	//"github.com/iami317/nuclei/v3/pkg/js/libs/mssql"
	//_ "github.com/iami317/nuclei/v3/pkg/js/libs/mssql"

	"github.com/dop251/goja"
	"github.com/iami317/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/mssql")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			//"MSSQLClient": gojs.GetClassConstructor[mssql.MSSQLClient](&mssql.MSSQLClient{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
