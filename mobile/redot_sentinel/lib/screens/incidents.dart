import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../api.dart';
import '../models.dart';
import '../theme.dart';
import 'ticket_detail.dart';

class IncidentsScreen extends StatefulWidget {
  const IncidentsScreen({super.key});
  @override
  State<IncidentsScreen> createState() => _IncidentsScreenState();
}

class _IncidentsScreenState extends State<IncidentsScreen> {
  Future<List<Incident>>? _future;
  bool _openOnly = false;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    setState(() => _future = Api.instance.incidents(openOnly: _openOnly));
    await _future;
  }

  Color _sevColor(String s) {
    switch (s) {
      case 'critical': return redotRed;
      case 'warning':  return const Color(0xFFF59E0B);
      default:         return const Color(0xFF3B82F6);
    }
  }

  IconData _typeIcon(String t) {
    switch (t) {
      case 'site_down':     return Icons.cloud_off;
      case 'ssl_expiring':
      case 'ssl_expired':   return Icons.lock_clock;
      case 'threat_spike':  return Icons.shield_outlined;
      case 'config_drift':  return Icons.settings_suggest;
      case 'cert_renewed':  return Icons.verified;
      default:              return Icons.warning_amber;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Incidents'),
        actions: [
          IconButton(
            tooltip: _openOnly ? 'Show all' : 'Show open only',
            onPressed: () { setState(() => _openOnly = !_openOnly); _reload(); },
            icon: Icon(_openOnly ? Icons.filter_alt : Icons.filter_alt_outlined,
                color: _openOnly ? redotRed : null),
          ),
        ],
      ),
      body: RefreshIndicator(
        color: redotRed,
        onRefresh: _reload,
        child: FutureBuilder<List<Incident>>(
          future: _future,
          builder: (ctx, snap) {
            if (snap.connectionState == ConnectionState.waiting) {
              return const Center(child: CircularProgressIndicator(color: redotRed));
            }
            if (snap.hasError) return _errorView(snap.error!);
            final list = snap.data ?? [];
            if (list.isEmpty) {
              return ListView(children: [
                Padding(
                  padding: const EdgeInsets.all(40),
                  child: Column(children: [
                    const Icon(Icons.check_circle_outline, size: 48, color: Color(0xFF10B981)),
                    const SizedBox(height: 12),
                    Text(_openOnly ? 'No open incidents' : 'No incidents on record',
                        style: const TextStyle(color: redotMuted)),
                  ]),
                ),
              ]);
            }
            return ListView.separated(
              padding: const EdgeInsets.all(16),
              itemCount: list.length,
              separatorBuilder: (_, __) => const SizedBox(height: 8),
              itemBuilder: (_, i) {
                final inc = list[i];
                return Card(
                  child: ListTile(
                    leading: CircleAvatar(
                      backgroundColor: _sevColor(inc.severity).withOpacity(0.15),
                      child: Icon(_typeIcon(inc.type), color: _sevColor(inc.severity)),
                    ),
                    title: Text(inc.zoneName ?? 'Zone #${inc.zoneId ?? "?"}'),
                    subtitle: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(inc.type, style: const TextStyle(fontWeight: FontWeight.w500)),
                        const SizedBox(height: 2),
                        Text(
                          inc.isOpen
                              ? 'Open since ${DateFormat('MMM d, HH:mm').format(inc.startedAt.toLocal())}'
                              : 'Resolved ${DateFormat('MMM d, HH:mm').format(inc.endedAt!.toLocal())}',
                          style: TextStyle(
                            color: inc.isOpen ? redotRed : redotMuted,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                    trailing: inc.isOpen
                        ? Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: redotRed.withOpacity(0.12),
                              borderRadius: BorderRadius.circular(20),
                            ),
                            child: const Text('OPEN',
                                style: TextStyle(color: redotRed,
                                    fontSize: 11, fontWeight: FontWeight.w700)),
                          )
                        : const Icon(Icons.check_circle, color: Color(0xFF10B981)),
                    onTap: () async {
                      await Navigator.of(context).push(MaterialPageRoute(
                        builder: (_) => IncidentDetailScreen(incidentId: inc.id),
                      ));
                      _reload();
                    },
                  ),
                );
              },
            );
          },
        ),
      ),
    );
  }

  Widget _errorView(Object e) => ListView(children: [
    Padding(
      padding: const EdgeInsets.all(40),
      child: Column(children: [
        const Icon(Icons.cloud_off, size: 48, color: redotMuted),
        const SizedBox(height: 12),
        Text(e.toString(), textAlign: TextAlign.center, style: const TextStyle(color: redotMuted)),
        const SizedBox(height: 12),
        TextButton(onPressed: _reload, child: const Text('Retry')),
      ]),
    ),
  ]);
}

class IncidentDetailScreen extends StatefulWidget {
  final int incidentId;
  const IncidentDetailScreen({super.key, required this.incidentId});
  @override
  State<IncidentDetailScreen> createState() => _IncidentDetailScreenState();
}

class _IncidentDetailScreenState extends State<IncidentDetailScreen> {
  Future<IncidentDetail>? _future;

  @override
  void initState() {
    super.initState();
    _future = Api.instance.incident(widget.incidentId);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Incident #${widget.incidentId}')),
      body: FutureBuilder<IncidentDetail>(
        future: _future,
        builder: (ctx, snap) {
          if (snap.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator(color: redotRed));
          }
          if (snap.hasError) {
            return Padding(
              padding: const EdgeInsets.all(24),
              child: Text(snap.error.toString(), style: const TextStyle(color: redotMuted)),
            );
          }
          final i = snap.data!;
          final dt = DateFormat('yyyy-MM-dd HH:mm');
          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Row(children: [
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: (i.severity == 'critical' ? redotRed : const Color(0xFFF59E0B)).withOpacity(0.12),
                          borderRadius: BorderRadius.circular(20),
                        ),
                        child: Text(i.severity.toUpperCase(),
                            style: TextStyle(color: i.severity == 'critical' ? redotRed : const Color(0xFFB45309),
                                fontWeight: FontWeight.w700, fontSize: 12)),
                      ),
                      const SizedBox(width: 8),
                      Text(i.type, style: const TextStyle(fontWeight: FontWeight.w600)),
                    ]),
                    const SizedBox(height: 12),
                    Text(i.zoneName ?? 'Zone #${i.zoneId ?? "?"}',
                        style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
                    const SizedBox(height: 12),
                    _row(Icons.schedule, 'Started ${dt.format(i.startedAt.toLocal())}'),
                    if (i.endedAt != null) ...[
                      const SizedBox(height: 4),
                      _row(Icons.check_circle_outline, 'Ended ${dt.format(i.endedAt!.toLocal())}'),
                    ] else ...[
                      const SizedBox(height: 4),
                      const Row(children: [
                        Icon(Icons.error_outline, size: 14, color: redotRed),
                        SizedBox(width: 6),
                        Text('Still open', style: TextStyle(color: redotRed, fontWeight: FontWeight.w600)),
                      ]),
                    ],
                  ]),
                ),
              ),
              if (i.summary != null && i.summary!.isNotEmpty) ...[
                const SizedBox(height: 8),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      const Text('SUMMARY', style: TextStyle(
                          fontSize: 11, letterSpacing: 1.2, color: redotMuted,
                          fontWeight: FontWeight.w700)),
                      const SizedBox(height: 8),
                      Text(i.summary!),
                    ]),
                  ),
                ),
              ],
              if (i.ticketId != null) ...[
                const SizedBox(height: 8),
                Card(
                  child: ListTile(
                    leading: const Icon(Icons.confirmation_num_outlined, color: redotRed),
                    title: Text('Linked ticket #${i.ticketId}'),
                    subtitle: Text('${i.ticketPriority?.toUpperCase() ?? "-"} · ${i.ticketStatus ?? "-"}'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => Navigator.of(context).push(MaterialPageRoute(
                      builder: (_) => TicketDetailScreen(ticketId: i.ticketId!),
                    )),
                  ),
                ),
              ],
            ],
          );
        },
      ),
    );
  }

  Widget _row(IconData ic, String s) => Row(children: [
    Icon(ic, size: 14, color: redotMuted),
    const SizedBox(width: 6),
    Expanded(child: Text(s, style: const TextStyle(color: redotMuted, fontSize: 13))),
  ]);
}
