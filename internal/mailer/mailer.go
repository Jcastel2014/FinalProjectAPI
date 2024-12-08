package mailer

import (
	"bytes"
	"embed"
	"text/template"
	"time"

	"github.com/go-mail/mail/v2"
)

/*
When we build our app for production, we want to include the templates
so we will use the go emded feature which creates a virtual file system
for us. To do this, we will use a special syntax that looks like a comment
but it is not a comment '//go:embed "templates"', it is a directive to Go
to build a virtual filesystem for the 'templates directory'

Cont'd on next slide
*/

// not using separate server to send email
//
//go:embed "templates"
var templateFS embed.FS //embedding the templates files into the program

// connection to mail /smtp  server
type Mailer struct {
	dailer *mail.Dialer
	sender string
}

// smtp connection with our credentials from mailtrap.io
func New(host string, port int, username, password, sender string) Mailer {
	dailer := mail.NewDialer(host, port, username, password)
	dailer.Timeout = 5 * time.Second

	return Mailer{
		dailer: dailer,
		sender: sender,
	}
}

//send the email to the user. data paremeter used for dynamic data injection into the template

func (m *Mailer) Send(recipient, templateFile string, data any) error {

	tmpl, err := template.New("email").ParseFS(templateFS, "templates/"+templateFile)
	if err != nil {
		return err
	}
	subject := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(subject, "subject", data)
	if err != nil {
		return err
	}
	htmlBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(htmlBody, "htmlBody", data)
	if err != nil {
		return err
	}

	plainBody := new(bytes.Buffer)
	err = tmpl.ExecuteTemplate(plainBody, "plainBody", data)

	//crafting the message from the parts above
	msg := mail.NewMessage()
	msg.SetHeader("To", recipient)
	msg.SetHeader("From", m.sender)
	msg.SetHeader("Subject", subject.String())
	msg.SetBody("text/plain", plainBody.String())
	msg.AddAlternative("text/html", htmlBody.String())

	for i := 1; i <= 3; i++ {
		err = m.dailer.DialAndSend(msg)
		if err == nil { //everything worked
			return nil
		}

		//wait a while and trying again if failure
		time.Sleep(500 * time.Millisecond)
	}

	return err //did not work, no longer trying
}
