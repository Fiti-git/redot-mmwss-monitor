/// Typed views over the JSON the v1 backend returns. We keep them simple —
/// extra fields are tolerated and ignored.

class CurrentUser {
  final int id;
  final String email;
  final String name;
  final String role;
  CurrentUser({required this.id, required this.email, required this.name, required this.role});

  factory CurrentUser.fromJson(Map<String, dynamic> j) => CurrentUser(
    id: j['id'] as int,
    email: j['email'] as String,
    name: j['name'] as String? ?? '',
    role: j['role'] as String? ?? 'engineer',
  );
}

class DashboardStats {
  final int zones;
  final int openIncidents;
  final int requests24h;
  final int threats24h;
  final double hitRatio;
  DashboardStats({
    required this.zones, required this.openIncidents,
    required this.requests24h, required this.threats24h, required this.hitRatio,
  });
  factory DashboardStats.fromJson(Map<String, dynamic> j) => DashboardStats(
    zones: (j['zones'] ?? 0) as int,
    openIncidents: (j['open_incidents'] ?? 0) as int,
    requests24h: (j['requests_24h'] ?? 0) as int,
    threats24h: (j['threats_24h'] ?? 0) as int,
    hitRatio: (j['hit_ratio'] ?? 0).toDouble(),
  );
}

class TicketCounters {
  final int openTotal;
  final Map<String, int> byPriority;
  TicketCounters({required this.openTotal, required this.byPriority});
  factory TicketCounters.fromJson(Map<String, dynamic> j) => TicketCounters(
    openTotal: (j['open_total'] ?? 0) as int,
    byPriority: Map<String, int>.from((j['by_priority'] ?? {}) as Map),
  );
}

class DashboardData {
  final DashboardStats stats;
  final TicketCounters tickets;
  final Map<String, dynamic> security;
  final Map<String, dynamic> uptime24h;
  DashboardData({required this.stats, required this.tickets, required this.security, required this.uptime24h});
  factory DashboardData.fromJson(Map<String, dynamic> j) => DashboardData(
    stats: DashboardStats.fromJson(j['stats'] as Map<String, dynamic>),
    tickets: TicketCounters.fromJson(j['tickets'] as Map<String, dynamic>),
    security: Map<String, dynamic>.from(j['security'] as Map),
    uptime24h: Map<String, dynamic>.from(j['uptime_24h'] as Map),
  );
}

class SlaState {
  final String responseState;
  final String resolutionState;
  final int responseElapsedS;
  final int resolutionElapsedS;
  SlaState({
    required this.responseState, required this.resolutionState,
    required this.responseElapsedS, required this.resolutionElapsedS,
  });
  factory SlaState.fromJson(Map<String, dynamic> j) => SlaState(
    responseState: j['response_state'] as String? ?? 'pending',
    resolutionState: j['resolution_state'] as String? ?? 'pending',
    responseElapsedS: (j['response_elapsed_s'] ?? 0) as int,
    resolutionElapsedS: (j['resolution_elapsed_s'] ?? 0) as int,
  );
}

class Ticket {
  final int id;
  final String title;
  final String priority;
  final String status;
  final String category;
  final String? zoneName;
  final DateTime openedAt;
  final DateTime? responseAt;
  final DateTime? resolvedAt;
  final String? openedByEmail;
  final String? assignedToEmail;
  final SlaState sla;

  Ticket({
    required this.id, required this.title, required this.priority,
    required this.status, required this.category, required this.zoneName,
    required this.openedAt, required this.responseAt, required this.resolvedAt,
    required this.openedByEmail, required this.assignedToEmail, required this.sla,
  });

  factory Ticket.fromJson(Map<String, dynamic> j) => Ticket(
    id: j['id'] as int,
    title: j['title'] as String,
    priority: j['priority'] as String,
    status: j['status'] as String,
    category: j['category'] as String? ?? 'other',
    zoneName: j['zone_name'] as String?,
    openedAt: DateTime.parse(j['opened_at'] as String),
    responseAt: j['response_at'] != null ? DateTime.parse(j['response_at'] as String) : null,
    resolvedAt: j['resolved_at'] != null ? DateTime.parse(j['resolved_at'] as String) : null,
    openedByEmail: j['opened_by_email'] as String?,
    assignedToEmail: j['assigned_to_email'] as String?,
    sla: SlaState.fromJson(j['sla'] as Map<String, dynamic>),
  );
}

class TicketEvent {
  final int id;
  final DateTime ts;
  final String eventType;
  final Map<String, dynamic>? details;
  final String? userEmail;
  TicketEvent({required this.id, required this.ts, required this.eventType,
               required this.details, required this.userEmail});
  factory TicketEvent.fromJson(Map<String, dynamic> j) => TicketEvent(
    id: j['id'] as int,
    ts: DateTime.parse(j['ts'] as String),
    eventType: j['event_type'] as String,
    details: j['details'] as Map<String, dynamic>?,
    userEmail: j['user_email'] as String?,
  );
}

class Incident {
  final int id;
  final int? zoneId;
  final String? zoneName;
  final String type;
  final String severity;
  final DateTime startedAt;
  final DateTime? endedAt;
  final String? summary;
  final bool isOpen;
  Incident({
    required this.id, required this.zoneId, required this.zoneName,
    required this.type, required this.severity,
    required this.startedAt, required this.endedAt, required this.summary,
    required this.isOpen,
  });
  factory Incident.fromJson(Map<String, dynamic> j) => Incident(
    id: j['id'] as int,
    zoneId: j['zone_id'] as int?,
    zoneName: j['zone_name'] as String?,
    type: j['type'] as String,
    severity: j['severity'] as String,
    startedAt: DateTime.parse(j['started_at'] as String),
    endedAt: j['ended_at'] != null ? DateTime.parse(j['ended_at'] as String) : null,
    summary: j['summary'] as String?,
    isOpen: (j['is_open'] ?? false) as bool,
  );
}

class IncidentDetail extends Incident {
  final int? ticketId;
  final String? ticketStatus;
  final String? ticketPriority;
  IncidentDetail({
    required super.id, required super.zoneId, required super.zoneName,
    required super.type, required super.severity,
    required super.startedAt, required super.endedAt, required super.summary,
    required super.isOpen,
    required this.ticketId, required this.ticketStatus, required this.ticketPriority,
  });
  factory IncidentDetail.fromJson(Map<String, dynamic> j) => IncidentDetail(
    id: j['id'] as int,
    zoneId: j['zone_id'] as int?,
    zoneName: j['zone_name'] as String?,
    type: j['type'] as String,
    severity: j['severity'] as String,
    startedAt: DateTime.parse(j['started_at'] as String),
    endedAt: j['ended_at'] != null ? DateTime.parse(j['ended_at'] as String) : null,
    summary: j['summary'] as String?,
    isOpen: (j['is_open'] ?? false) as bool,
    ticketId: j['ticket_id'] as int?,
    ticketStatus: j['ticket_status'] as String?,
    ticketPriority: j['ticket_priority'] as String?,
  );
}

class OriginHealthZone {
  final int zoneId;
  final String zoneName;
  final int checks24h;
  final int ok24h;
  final double? uptimePct24h;
  final double? avgLatencyMs;
  final bool? latestOk;
  final int? latestStatus;
  final Map<String, dynamic> aws;
  OriginHealthZone({
    required this.zoneId, required this.zoneName,
    required this.checks24h, required this.ok24h,
    required this.uptimePct24h, required this.avgLatencyMs,
    required this.latestOk, required this.latestStatus, required this.aws,
  });
  factory OriginHealthZone.fromJson(Map<String, dynamic> j) => OriginHealthZone(
    zoneId: j['zone_id'] as int,
    zoneName: j['zone_name'] as String,
    checks24h: (j['checks_24h'] ?? 0) as int,
    ok24h: (j['ok_24h'] ?? 0) as int,
    uptimePct24h: j['uptime_pct_24h'] == null ? null : (j['uptime_pct_24h'] as num).toDouble(),
    avgLatencyMs: j['avg_latency_ms'] == null ? null : (j['avg_latency_ms'] as num).toDouble(),
    latestOk: j['latest_ok'] as bool?,
    latestStatus: j['latest_status'] as int?,
    aws: Map<String, dynamic>.from(j['aws'] as Map),
  );
}

class Finding {
  final int id;
  final String title;
  final String severity;
  final String status;
  final int? zoneId;
  final String? zoneName;
  final DateTime? discoveredAt;
  final String? cve;
  final int? linkedTicketId;
  final String? linkedTicketStatus;
  Finding({
    required this.id, required this.title, required this.severity, required this.status,
    required this.zoneId, required this.zoneName, required this.discoveredAt,
    required this.cve, required this.linkedTicketId, required this.linkedTicketStatus,
  });
  factory Finding.fromJson(Map<String, dynamic> j) => Finding(
    id: j['id'] as int,
    title: j['title'] as String,
    severity: j['severity'] as String,
    status: j['status'] as String,
    zoneId: j['zone_id'] as int?,
    zoneName: j['zone_name'] as String?,
    discoveredAt: j['discovered_at'] != null ? DateTime.parse(j['discovered_at'] as String) : null,
    cve: j['cve_reference'] as String?,
    linkedTicketId: j['linked_ticket_id'] as int?,
    linkedTicketStatus: j['linked_ticket_status'] as String?,
  );
}

class FindingDetail extends Finding {
  final String? description;
  final String? reportTitle;
  final String? vendor;
  final DateTime? remediatedAt;
  final DateTime? verifiedAt;
  final String? vendorFindingId;
  FindingDetail({
    required super.id, required super.title, required super.severity, required super.status,
    required super.zoneId, required super.zoneName, required super.discoveredAt,
    required super.cve, required super.linkedTicketId, required super.linkedTicketStatus,
    required this.description, required this.reportTitle, required this.vendor,
    required this.remediatedAt, required this.verifiedAt, required this.vendorFindingId,
  });
  factory FindingDetail.fromJson(Map<String, dynamic> j) => FindingDetail(
    id: j['id'] as int,
    title: j['title'] as String,
    severity: j['severity'] as String,
    status: j['status'] as String,
    zoneId: j['zone_id'] as int?,
    zoneName: j['zone_name'] as String?,
    discoveredAt: j['discovered_at'] != null ? DateTime.parse(j['discovered_at'] as String) : null,
    cve: j['cve_reference'] as String?,
    linkedTicketId: j['linked_ticket_id'] as int?,
    linkedTicketStatus: j['linked_ticket_status'] as String?,
    description: j['description'] as String?,
    reportTitle: j['report_title'] as String?,
    vendor: j['vendor'] as String?,
    remediatedAt: j['remediated_at'] != null ? DateTime.parse(j['remediated_at'] as String) : null,
    verifiedAt: j['verified_at'] != null ? DateTime.parse(j['verified_at'] as String) : null,
    vendorFindingId: j['vendor_finding_id'] as String?,
  );
}

class PushPreferences {
  bool notifyP1;
  bool notifyScannerCritical;
  bool notifyHoneytoken;
  bool notifyReportReady;
  bool notifySlaWarning;
  PushPreferences({
    required this.notifyP1, required this.notifyScannerCritical,
    required this.notifyHoneytoken, required this.notifyReportReady,
    required this.notifySlaWarning,
  });
  factory PushPreferences.fromJson(Map<String, dynamic> j) => PushPreferences(
    notifyP1: (j['notify_p1'] ?? true) as bool,
    notifyScannerCritical: (j['notify_scanner_critical'] ?? true) as bool,
    notifyHoneytoken: (j['notify_honeytoken'] ?? true) as bool,
    notifyReportReady: (j['notify_report_ready'] ?? true) as bool,
    notifySlaWarning: (j['notify_sla_warning'] ?? true) as bool,
  );
}

class TicketDetail {
  final Ticket ticket;
  final String? description;
  final String? resolutionNotes;
  final String? rcaText;
  final List<TicketEvent> events;
  TicketDetail({required this.ticket, required this.description,
                required this.resolutionNotes, required this.rcaText,
                required this.events});
  factory TicketDetail.fromJson(Map<String, dynamic> j) => TicketDetail(
    ticket: Ticket.fromJson(j['ticket'] as Map<String, dynamic>),
    description: j['description'] as String?,
    resolutionNotes: j['resolution_notes'] as String?,
    rcaText: j['rca_text'] as String?,
    events: ((j['events'] as List?) ?? [])
        .map((e) => TicketEvent.fromJson(e as Map<String, dynamic>))
        .toList(),
  );
}
