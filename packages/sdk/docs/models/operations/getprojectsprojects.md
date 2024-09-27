# GetProjectsProjects

## Example Usage

```typescript
import { GetProjectsProjects } from "@vercel/sdk/models/operations/getprojects.js";

let value: GetProjectsProjects = {
  accountId: "<value>",
  crons: {
    enabledAt: 1523.55,
    disabledAt: 4174.86,
    updatedAt: 1312.89,
    deploymentId: "<value>",
    definitions: [
      {
        host: "vercel.com",
        path: "/api/crons/sync-something?hello=world",
        schedule: "0 0 * * *",
      },
    ],
  },
  directoryListing: false,
  id: "<id>",
  latestDeployments: [
    {
      createdAt: 6041.18,
      createdIn: "<value>",
      creator: {
        email: "Sonia_Lockman-Goodwin@yahoo.com",
        uid: "<value>",
        username: "Katrina.Klocko",
      },
      deploymentHostname: "<value>",
      name: "<value>",
      id: "<id>",
      plan: "pro",
      private: false,
      readyState: "INITIALIZING",
      type: "LAMBDAS",
      url: "https://sizzling-finger.org",
      userId: "<value>",
      previewCommentsEnabled: false,
    },
  ],
  name: "<value>",
  nodeVersion: "8.10.x",
  targets: {
    "key": {
      createdAt: 486.90,
      createdIn: "<value>",
      creator: {
        email: "Isabella_Heidenreich@gmail.com",
        uid: "<value>",
        username: "Meredith_Heaney",
      },
      deploymentHostname: "<value>",
      name: "<value>",
      id: "<id>",
      plan: "pro",
      private: false,
      readyState: "BUILDING",
      type: "LAMBDAS",
      url: "https://acidic-gastropod.name",
      userId: "<value>",
      previewCommentsEnabled: false,
    },
  },
};
```

## Fields

| Field                                                                                                            | Type                                                                                                             | Required                                                                                                         | Description                                                                                                      |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `accountId`                                                                                                      | *string*                                                                                                         | :heavy_check_mark:                                                                                               | N/A                                                                                                              |
| `analytics`                                                                                                      | [operations.GetProjectsAnalytics](../../models/operations/getprojectsanalytics.md)                               | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `speedInsights`                                                                                                  | [operations.GetProjectsSpeedInsights](../../models/operations/getprojectsspeedinsights.md)                       | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `autoExposeSystemEnvs`                                                                                           | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `autoAssignCustomDomains`                                                                                        | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `autoAssignCustomDomainsUpdatedBy`                                                                               | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `buildCommand`                                                                                                   | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `commandForIgnoringBuildStep`                                                                                    | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `connectConfigurationId`                                                                                         | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `connectBuildsEnabled`                                                                                           | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `createdAt`                                                                                                      | *number*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `customerSupportCodeVisibility`                                                                                  | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `crons`                                                                                                          | [operations.GetProjectsCrons](../../models/operations/getprojectscrons.md)                                       | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `dataCache`                                                                                                      | [operations.GetProjectsDataCache](../../models/operations/getprojectsdatacache.md)                               | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `deploymentExpiration`                                                                                           | [operations.GetProjectsDeploymentExpiration](../../models/operations/getprojectsdeploymentexpiration.md)         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `devCommand`                                                                                                     | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `directoryListing`                                                                                               | *boolean*                                                                                                        | :heavy_check_mark:                                                                                               | N/A                                                                                                              |
| `installCommand`                                                                                                 | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `env`                                                                                                            | [operations.GetProjectsEnv](../../models/operations/getprojectsenv.md)[]                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `framework`                                                                                                      | [operations.GetProjectsFramework](../../models/operations/getprojectsframework.md)                               | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `gitForkProtection`                                                                                              | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `gitLFS`                                                                                                         | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `id`                                                                                                             | *string*                                                                                                         | :heavy_check_mark:                                                                                               | N/A                                                                                                              |
| `latestDeployments`                                                                                              | [operations.GetProjectsLatestDeployments](../../models/operations/getprojectslatestdeployments.md)[]             | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `link`                                                                                                           | *operations.GetProjectsLink*                                                                                     | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `name`                                                                                                           | *string*                                                                                                         | :heavy_check_mark:                                                                                               | N/A                                                                                                              |
| `nodeVersion`                                                                                                    | [operations.GetProjectsNodeVersion](../../models/operations/getprojectsnodeversion.md)                           | :heavy_check_mark:                                                                                               | N/A                                                                                                              |
| `optionsAllowlist`                                                                                               | [operations.GetProjectsOptionsAllowlist](../../models/operations/getprojectsoptionsallowlist.md)                 | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `outputDirectory`                                                                                                | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `passiveConnectConfigurationId`                                                                                  | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `passwordProtection`                                                                                             | [operations.GetProjectsPasswordProtection](../../models/operations/getprojectspasswordprotection.md)             | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `productionDeploymentsFastLane`                                                                                  | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `publicSource`                                                                                                   | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `rootDirectory`                                                                                                  | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `serverlessFunctionRegion`                                                                                       | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `serverlessFunctionZeroConfigFailover`                                                                           | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `skewProtectionBoundaryAt`                                                                                       | *number*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `skewProtectionMaxAge`                                                                                           | *number*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `skipGitConnectDuringLink`                                                                                       | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `sourceFilesOutsideRootDirectory`                                                                                | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `enableAffectedProjectsDeployments`                                                                              | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `ssoProtection`                                                                                                  | [operations.GetProjectsSsoProtection](../../models/operations/getprojectsssoprotection.md)                       | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `targets`                                                                                                        | Record<string, [operations.GetProjectsTargets](../../models/operations/getprojectstargets.md)>                   | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `transferCompletedAt`                                                                                            | *number*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `transferStartedAt`                                                                                              | *number*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `transferToAccountId`                                                                                            | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `transferredFromAccountId`                                                                                       | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `updatedAt`                                                                                                      | *number*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `live`                                                                                                           | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `enablePreviewFeedback`                                                                                          | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `enableProductionFeedback`                                                                                       | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `permissions`                                                                                                    | [operations.GetProjectsPermissions](../../models/operations/getprojectspermissions.md)                           | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `lastRollbackTarget`                                                                                             | [operations.GetProjectsLastRollbackTarget](../../models/operations/getprojectslastrollbacktarget.md)             | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `lastAliasRequest`                                                                                               | [operations.GetProjectsLastAliasRequest](../../models/operations/getprojectslastaliasrequest.md)                 | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `hasFloatingAliases`                                                                                             | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `protectionBypass`                                                                                               | Record<string, [operations.GetProjectsProtectionBypass](../../models/operations/getprojectsprotectionbypass.md)> | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `hasActiveBranches`                                                                                              | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `trustedIps`                                                                                                     | *operations.GetProjectsTrustedIps*                                                                               | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `gitComments`                                                                                                    | [operations.GetProjectsGitComments](../../models/operations/getprojectsgitcomments.md)                           | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `paused`                                                                                                         | *boolean*                                                                                                        | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `concurrencyBucketName`                                                                                          | *string*                                                                                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `webAnalytics`                                                                                                   | [operations.GetProjectsWebAnalytics](../../models/operations/getprojectswebanalytics.md)                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `security`                                                                                                       | [operations.GetProjectsSecurity](../../models/operations/getprojectssecurity.md)                                 | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `oidcTokenConfig`                                                                                                | [operations.GetProjectsOidcTokenConfig](../../models/operations/getprojectsoidctokenconfig.md)                   | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |
| `tier`                                                                                                           | [operations.GetProjectsTier](../../models/operations/getprojectstier.md)                                         | :heavy_minus_sign:                                                                                               | N/A                                                                                                              |