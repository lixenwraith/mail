package mail_test

import (
	"context"
	"log"
	"time"

	"github.com/lixenwraith/mail"
)

func ExampleClient_Send() {
	client, err := mail.NewClient(mail.Config{
		Host: "smtp.example.org", Port: 587, Username: "app", Password: "secret",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err = client.Send(ctx, &mail.Message{
		From:    "App <app@example.org>",
		To:      []string{"someone@example.net"},
		Subject: "Your report",
		Text:    "The report is attached.\n",
		Attachments: []mail.Attachment{
			{Filename: "report.csv", Content: []byte("day,count\n1,42\n")},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
