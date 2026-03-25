package scanner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
)

type BeanstalkAuditResults struct {
	Environments          []types.EnvironmentDescription                `json:"Environments"`
	ConfigurationSettings map[string][]types.ConfigurationOptionSetting `json:"ConfigurationSettings"`
}

// AuditBeanstalk gathers all required Elastic Beanstalk security findings.
func AuditBeanstalk(ctx context.Context, cfg aws.Config) (BeanstalkAuditResults, error) {
	client := elasticbeanstalk.NewFromConfig(cfg)
	var results BeanstalkAuditResults
	results.ConfigurationSettings = make(map[string][]types.ConfigurationOptionSetting)

	var nextToken *string
	for {
		envsOut, err := client.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return results, err
		}
		results.Environments = append(results.Environments, envsOut.Environments...)

		if envsOut.NextToken == nil {
			break
		}
		nextToken = envsOut.NextToken
	}

	for _, env := range results.Environments {
		if env.EnvironmentName == nil || env.ApplicationName == nil {
			continue
		}

		cfgOut, err := client.DescribeConfigurationSettings(ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
			ApplicationName: env.ApplicationName,
			EnvironmentName: env.EnvironmentName,
		})
		if err == nil && len(cfgOut.ConfigurationSettings) > 0 {
			results.ConfigurationSettings[*env.EnvironmentName] = cfgOut.ConfigurationSettings[0].OptionSettings
		}
	}

	return results, nil
}
