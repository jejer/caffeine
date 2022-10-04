package main

import (
	"embed"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
)

//go:embed files/*
var files embed.FS

func main() {
	cacheMap := make(map[string][]byte)
	app := fiber.New()

	app.Use("/", func(c *fiber.Ctx) error {
		log.Println(c.Method(), c.Path())
		return c.Next()
	})

	app.Use("/", filesystem.New(filesystem.Config{
		Root:       http.FS(files),
		PathPrefix: "files/exploit",
	}))

	app.Get("/cache", func(c *fiber.Ctx) error {
		ua := string(c.Request().Header.UserAgent())
		data, exist := cacheMap[ua]
		if !exist {
			log.Println("Cache missing: " + ua)
			return fiber.ErrNotFound
		}
		return c.Status(fiber.StatusOK).Send(data)
	})

	app.Post("/cache", func(c *fiber.Ctx) error {
		ua := string(c.Request().Header.UserAgent())
		rsp := map[string]interface{}{}
		if err := json.Unmarshal(c.Body(), &rsp); err != nil {
			log.Printf("Error: %v", err)
			return fiber.ErrBadRequest
		}
		msg, err := json.Marshal(rsp["msg"])
		if err != nil {
			log.Printf("Error: %v", err)
			return fiber.ErrBadRequest
		}
		cacheMap[ua] = msg
		return c.SendStatus(fiber.StatusOK)
	})

	app.Post("/log", func(c *fiber.Ctx) error {
		log.Println("Log: " + string(c.Body()))
		return c.SendStatus(fiber.StatusOK)
	})

	app.Post("/error", func(c *fiber.Ctx) error {
		log.Println("Error: " + string(c.Body()))
		return c.SendStatus(fiber.StatusOK)
	})

	// log.Fatal(app.Listen(":8080"))
	log.Fatal(app.Listen(":80"))
}
