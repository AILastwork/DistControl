using System;
using System.Collections.Generic;

namespace DistControl.Server
{
    public sealed class ServerData
    {
        public int SchemaVersion = 4;
        public List<ClientRecord> Clients = new List<ClientRecord>();
        public List<PendingEnrollmentRecord> PendingEnrollments = new List<PendingEnrollmentRecord>();
        public List<CentralLogRecord> Logs = new List<CentralLogRecord>();
        public List<UpdateRecord> Updates = new List<UpdateRecord>();
        public List<AuditRecord> Audit = new List<AuditRecord>();
        public List<ClientCommandRecord> Commands = new List<ClientCommandRecord>();
        public HubConfiguration Hubs = new HubConfiguration();
    }

    public sealed class HubConfiguration
    {
        public string Revision = "";
        public string ManualHubs = "";
        public string DiscoveredManualHubs = "";
        public string UpdatedUtc = "";
        public string UpdatedBy = "";
    }

    public sealed class HubConfigurationUpdateRequest
    {
        public string ManualHubs = "";
    }

    public sealed class PendingEnrollmentRecord
    {
        public string Id = "";
        public string RequestTokenHash = "";
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string PolicyJson = "";
        public string RequestedUtc = "";
        public string LastRequestUtc = "";
        public string LastIpAddress = "";
        public bool Approved = false;
        public bool Rejected = false;
        public string DecidedBy = "";
        public string DecidedUtc = "";
    }

    public sealed class ClientRecord
    {
        public string Id = "";
        public string TokenHash = "";
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string LastSeenUtc = "";
        public string LastIpAddress = "";
        public string LastNetworkStateJson = "";
        public string CurrentManualHubs = "";
        public string AppliedHubRevision = "";
        public string HubStatus = "";
        public string PolicyRevision = "";
        public string PolicyJson = "";
        public string AppliedPolicyRevision = "";
        public string DesiredVersion = "";
        public string UpdateStatus = "";
        public string LastError = "";
    }

    public sealed class CentralLogRecord
    {
        public string Id = "";
        public string ClientId = "";
        public string ReceivedUtc = "";
        public string FileName = "";
        public string Text = "";
    }

    public sealed class UpdateRecord
    {
        public string Version = "";
        public string FileName = "";
        public string Sha256 = "";
        public long Size = 0;
        public string PublishedUtc = "";
        public string PublishedBy = "";
    }

    public sealed class AuditRecord
    {
        public string TimestampUtc = "";
        public string Actor = "";
        public string Action = "";
        public string Target = "";
        public string Details = "";
    }

    public sealed class ClientCommandRecord
    {
        public string Id = "";
        public string ClientId = "";
        public string Type = "";
        public string Status = "";
        public string RequestedUtc = "";
        public string RequestedBy = "";
        public string CompletedUtc = "";
        public string Result = "";
    }

    public sealed class ClientCommandResponse
    {
        public bool Available = false;
        public string Id = "";
        public string Type = "";
    }

    public sealed class ClientCommandResultRequest
    {
        public bool Success = false;
        public string Message = "";
    }

    public sealed class EnrollRequest
    {
        public string RequestToken = "";
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string PolicyJson = "";
    }

    public sealed class EnrollResponse
    {
        public bool Approved = false;
        public bool Rejected = false;
        public string RequestId = "";
        public string Status = "";
        public string ClientId = "";
        public string ClientToken = "";
        public string PolicyRevision = "";
    }

    public sealed class PendingEnrollmentSummary
    {
        public string Id = "";
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string RequestedUtc = "";
        public string LastRequestUtc = "";
        public string LastIpAddress = "";
        public string Status = "";
        public string DecidedBy = "";
        public string DecidedUtc = "";
    }

    public sealed class HeartbeatRequest
    {
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string AppliedPolicyRevision = "";
        public string UpdateStatus = "";
        public string LastError = "";
        public string NetworkStateJson = "";
        public string CurrentManualHubs = "";
        public string AppliedHubRevision = "";
        public string HubStatus = "";
    }

    public sealed class PolicyResponse
    {
        public string Revision = "";
        public string PolicyJson = "";
    }

    public sealed class PolicyUpdateRequest
    {
        public string ExpectedRevision = "";
        public string PolicyJson = "";
        public string Actor = "";
        public bool ConfirmMassExpansion = false;
    }

    public sealed class LogUploadRequest
    {
        public List<LogUploadItem> Items = new List<LogUploadItem>();
    }

    public sealed class LogUploadItem
    {
        public string Id = "";
        public string FileName = "";
        public string Text = "";
    }

    public sealed class UpdateManifestResponse
    {
        public bool Available = false;
        public string Version = "";
        public string Sha256 = "";
        public long Size = 0;
        public string DownloadPath = "";
    }

    public sealed class UpdateAssignmentRequest
    {
        public string Version = "";
        public string Actor = "";
    }

    public sealed class ClientSummary
    {
        public string Id = "";
        public string MachineName = "";
        public string UserName = "";
        public string AppVersion = "";
        public string AgentVersion = "";
        public string LastSeenUtc = "";
        public string LastIpAddress = "";
        public string PolicyRevision = "";
        public string AppliedPolicyRevision = "";
        public string DesiredVersion = "";
        public string UpdateStatus = "";
        public string LastError = "";
        public string AppliedHubRevision = "";
        public string HubStatus = "";
        public string CommandStatus = "";
        public string CommandResult = "";
        public bool Online = false;
    }
}
