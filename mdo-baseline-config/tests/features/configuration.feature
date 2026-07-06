# Feature: Configuration Validation

## Scenario: Validate standard baseline configuration
- Given a standard baseline configuration file
- When validation is run
- Then all required fields should be present
- And protection level should be "Standard"
- And all policies should be defined
- And configuration should pass schema validation

## Scenario: Validate strict baseline configuration
- Given a strict baseline configuration file
- When validation is run
- Then all required fields should be present
- And protection level should be "Strict"
- And advanced threat protection features should be enabled
- And configuration should pass schema validation

## Scenario: Reject invalid configuration
- Given an invalid configuration file
- And the file is missing required fields
- When validation is run
- Then validation should fail
- And detailed error messages should be provided

---

# Feature: Policy Deployment

## Scenario: Deploy anti-phishing policy with threshold
- Given a valid MDO configuration
- When deploying anti-phishing policy
- Then policy should be created with correct name
- And phishing threshold should match configuration
- And recipient targeting should be applied

## Scenario: Deploy multiple policies in sequence
- Given a configuration with multiple policy types
- When deploying all policies
- Then each policy should be created successfully
- And policy priority should be respected
- And no conflicts should occur

## Scenario: Handle deployment in audit mode
- Given a configuration set to Audit mode
- When deploying policies
- Then policies should detect threats
- And no emails should be blocked
- And all actions should be logged

---

# Feature: Configuration Customization

## Scenario: Modify protection thresholds
- Given a baseline configuration
- When customizing phishing thresholds
- Then configuration should validate
- And modified thresholds should be applied on deployment
- And false positive rate should adjust accordingly

## Scenario: Add trusted sender to allow list
- Given a configuration with allow/block lists
- When adding a trusted sender
- Then the sender should be added to allowed senders
- And configuration should remain valid
- And deployment should apply the allow rule

---

# Feature: Phased Rollout

## Scenario: Deploy pilot phase to 10% of users
- Given a pilot phase configuration
- When targeting 10-20% of users
- Then policies should apply only to pilot group
- And audit mode should be active
- And monitoring should show detection without blocking

## Scenario: Transition from pilot to staged phase
- Given a completed pilot phase
- When moving to staged phase
- Then deployment should target 50-70% of users
- And mode can be switched to Enforce
- And previous pilot targeting can be expanded

---

# Feature: Allow/Block List Management

## Scenario: Add malicious domain to block list
- Given a block list in configuration
- When adding a malicious domain
- Then domain should be blocked for all users
- And emails from domain should be rejected
- And log should show blocked message

## Scenario: Add vendor domain to allow list
- Given an allow list in configuration
- When adding vendor domain
- Then vendor emails should bypass certain checks
- And mail should flow normally
- And exceptions should be logged

---

# Feature: Error Handling

## Scenario: Handle missing configuration file
- Given a missing configuration file
- When attempting to validate or deploy
- Then clear error message should be shown
- And operation should fail gracefully
- And no partial changes should be made

## Scenario: Handle connection failure to Exchange Online
- Given a connection to Exchange Online fails
- When attempting deployment
- Then error should be logged
- And helpful troubleshooting steps should be provided
- And user should know next steps

---

# Feature: Logging and Audit Trail

## Scenario: Create detailed deployment log
- Given a deployment operation
- When deployment completes
- Then log file should be created
- And log should contain timestamped entries
- And all actions should be recorded

## Scenario: Include dry-run details in log
- Given a dry-run operation
- When dry-run completes
- Then log should show what would be deployed
- And log should include all policy details
- And actual changes should NOT be recorded
