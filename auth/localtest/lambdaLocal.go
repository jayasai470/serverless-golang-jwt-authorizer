package main

import (
	"encoding/json"
	"github.com/aws/aws-lambda-go/events"
	"io/ioutil"
	"log"
)

func main() {

	file, _ := ioutil.ReadFile("C:\\Users\\j.muppala\\git\\test\\go-test\\auth\\localtest\\auth.json")

	data := events.APIGatewayProxyRequest{}

	_ = json.Unmarshal([]byte(file), &data)
	response, err := Run(Input{
		Port:    8001,
		Payload: data,
	})

	if err != nil {
		log.Fatalln(err)
	} else {
		log.Println(string(response))
	}
}
