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
