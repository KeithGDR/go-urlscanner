package config

import (
	"encoding/json"
	"io/ioutil"
)

const defaultConfigPath = "config.json"

func ParseConfig(configObj interface{}) error {
	file, err := ioutil.ReadFile(defaultConfigPath)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(file, &configObj); err != nil {
		return err
	}

	return nil
}
