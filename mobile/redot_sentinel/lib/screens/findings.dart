import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../api.dart';
import '../models.dart';
import '../theme.dart';
import 'ticket_detail.dart';

Color findingSevColor(String s) {
  switch (s) {
    case 'critical': return redotRed;
    case 'high':     return const Color(0xFFEA580C);
    case 'medium':   return const Color(0xFFF59E0B);
    case 'low':      return const Color(0xFF3B82F6);
    default:         return const Color(0xFF6B7280);
  }
}

class FindingsScreen extends StatefulWidget {
  const FindingsScreen({super.key});
  @override
  State<FindingsScreen> createState() => _FindingsScreenState();
}

class _FindingsScreenState extends State<FindingsScreen> {
  Future<List<Finding>>? _future;
  String? _severity;
  String? _status;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    setState(() => _future = Api.instance.findings(severity: _severity, status: _status));
    await _future;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scanner findings'),
        actions: [
          PopupMenuButton<String>(
            tooltip: 'Filter',
            icon: const Icon(Icons.filter_list),
            onSelected: (v) {
              setState(() {
                if (v.startsWith('s:')) _severity = v == 's:all' ? null : v.substring(2);
                if (v.startsWith('x:')) _status = v == 'x:all' ? null : v.substring(2);
              });
              _reload();
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 's:all',      child: Text('All severities')),
              PopupMenuItem(value: 's:critical', child: Text('Critical only')),
              PopupMenuItem(value: 's:high',     child: Text('High only')),
              PopupMenuItem(value: 's:medium',   child: Text('Medium only')),
              PopupMenuItem(value: 's:low',      child: Text('Low only')),
              PopupMenuDivider(),
              PopupMenuItem(value: 'x:all',         child: Text('All statuses')),
              PopupMenuItem(value: 'x:open',        child: Text('Open')),
              PopupMenuItem(value: 'x:in_progress', child: Text('In progress')),
              PopupMenuItem(value: 'x:verified',    child: Text('Verified')),
            ],
          ),
        ],
      ),
      body: Column(children: [
        if (_severity != null || _status != null)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: Wrap(spacing: 8, children: [
              if (_severity != null)
                Chip(
                  label: Text(_severity!.toUpperCase()),
                  backgroundColor: findingSevColor(_severity!).withOpacity(0.12),
                  onDeleted: () { setState(() => _severity = null); _reload(); },
                ),
              if (_status != null)
                Chip(
                  label: Text(_status!),
                  onDeleted: () { setState(() => _status = null); _reload(); },
                ),
            ]),
          ),
        Expanded(
          child: RefreshIndicator(
            color: redotRed,
            onRefresh: _reload,
            child: FutureBuilder<List<Finding>>(
              future: _future,
              builder: (ctx, snap) {
                if (snap.connectionState == ConnectionState.waiting) {
                  return const Center(child: CircularProgressIndicator(color: redotRed));
                }
                if (snap.hasError) {
                  return ListView(children: [
                    Padding(
                      padding: const EdgeInsets.all(40),
                      child: Column(children: [
                        const Icon(Icons.cloud_off, size: 48, color: redotMuted),
                        const SizedBox(height: 12),
                        Text(snap.error.toString(), textAlign: TextAlign.center,
                            style: const TextStyle(color: redotMuted)),
                        const SizedBox(height: 12),
                        TextButton(onPressed: _reload, child: const Text('Retry')),
                      ]),
                    ),
                  ]);
                }
                final list = snap.data ?? [];
                if (list.isEmpty) {
                  return ListView(children: const [
                    Padding(
                      padding: EdgeInsets.all(40),
                      child: Column(children: [
                        Icon(Icons.shield, size: 48, color: Color(0xFF10B981)),
                        SizedBox(height: 12),
                        Text('No findings match this filter',
                            style: TextStyle(color: redotMuted)),
                      ]),
                    ),
                  ]);
                }
                return ListView.separated(
                  padding: const EdgeInsets.all(16),
                  itemCount: list.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 8),
                  itemBuilder: (_, i) => _findingTile(list[i]),
                );
              },
            ),
          ),
        ),
      ]),
    );
  }

  Widget _findingTile(Finding f) {
    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: () async {
          await Navigator.of(context).push(MaterialPageRoute(
            builder: (_) => FindingDetailScreen(findingId: f.id),
          ));
          _reload();
        },
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: findingSevColor(f.severity).withOpacity(0.12),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Text(f.severity.toUpperCase(),
                    style: TextStyle(
                        color: findingSevColor(f.severity),
                        fontSize: 11, fontWeight: FontWeight.w700)),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: const Color(0xFFE5E7EB),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Text(f.status,
                    style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600)),
              ),
              if (f.cve != null) ...[
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: const Color(0xFFEEF2FF),
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Text(f.cve!,
                      style: const TextStyle(fontSize: 10, fontWeight: FontWeight.w700,
                          color: Color(0xFF4338CA))),
                ),
              ],
            ]),
            const SizedBox(height: 8),
            Text(f.title, style: const TextStyle(fontWeight: FontWeight.w600)),
            const SizedBox(height: 4),
            Row(children: [
              if (f.zoneName != null) ...[
                const Icon(Icons.public, size: 12, color: redotMuted),
                const SizedBox(width: 4),
                Text(f.zoneName!, style: const TextStyle(fontSize: 12, color: redotMuted)),
              ],
              const Spacer(),
              if (f.discoveredAt != null)
                Text(DateFormat('MMM d').format(f.discoveredAt!.toLocal()),
                    style: const TextStyle(fontSize: 11, color: redotMuted)),
            ]),
            if (f.linkedTicketId != null) ...[
              const SizedBox(height: 4),
              Row(children: [
                const Icon(Icons.confirmation_num_outlined, size: 12, color: redotRed),
                const SizedBox(width: 4),
                Text('Ticket #${f.linkedTicketId} · ${f.linkedTicketStatus ?? "-"}',
                    style: const TextStyle(fontSize: 11, color: redotRed)),
              ]),
            ],
          ]),
        ),
      ),
    );
  }
}

class FindingDetailScreen extends StatefulWidget {
  final int findingId;
  const FindingDetailScreen({super.key, required this.findingId});
  @override
  State<FindingDetailScreen> createState() => _FindingDetailScreenState();
}

class _FindingDetailScreenState extends State<FindingDetailScreen> {
  Future<FindingDetail>? _future;

  @override
  void initState() {
    super.initState();
    _future = Api.instance.finding(widget.findingId);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Finding #${widget.findingId}')),
      body: FutureBuilder<FindingDetail>(
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
          final f = snap.data!;
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
                          color: findingSevColor(f.severity).withOpacity(0.12),
                          borderRadius: BorderRadius.circular(20),
                        ),
                        child: Text(f.severity.toUpperCase(),
                            style: TextStyle(color: findingSevColor(f.severity),
                                fontWeight: FontWeight.w700)),
                      ),
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: const Color(0xFFE5E7EB),
                          borderRadius: BorderRadius.circular(20),
                        ),
                        child: Text(f.status,
                            style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 12)),
                      ),
                    ]),
                    const SizedBox(height: 12),
                    Text(f.title, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
                    const SizedBox(height: 8),
                    if (f.cve != null) _row(Icons.bug_report, f.cve!),
                    if (f.zoneName != null) _row(Icons.public, f.zoneName!),
                    if (f.discoveredAt != null) _row(Icons.schedule, 'Discovered ${dt.format(f.discoveredAt!.toLocal())}'),
                    if (f.remediatedAt != null) _row(Icons.build, 'Remediated ${dt.format(f.remediatedAt!.toLocal())}'),
                    if (f.verifiedAt != null) _row(Icons.verified, 'Verified ${dt.format(f.verifiedAt!.toLocal())}'),
                    if (f.reportTitle != null) _row(Icons.description, '${f.reportTitle!}${f.vendor != null ? " · ${f.vendor!}" : ""}'),
                    if (f.vendorFindingId != null) _row(Icons.tag, f.vendorFindingId!),
                  ]),
                ),
              ),
              if (f.description != null && f.description!.isNotEmpty) ...[
                const SizedBox(height: 8),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      const Text('DESCRIPTION', style: TextStyle(
                          fontSize: 11, letterSpacing: 1.2, color: redotMuted,
                          fontWeight: FontWeight.w700)),
                      const SizedBox(height: 8),
                      Text(f.description!),
                    ]),
                  ),
                ),
              ],
              if (f.linkedTicketId != null) ...[
                const SizedBox(height: 8),
                Card(
                  child: ListTile(
                    leading: const Icon(Icons.confirmation_num_outlined, color: redotRed),
                    title: Text('Linked ticket #${f.linkedTicketId}'),
                    subtitle: Text(f.linkedTicketStatus ?? '-'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => Navigator.of(context).push(MaterialPageRoute(
                      builder: (_) => TicketDetailScreen(ticketId: f.linkedTicketId!),
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

  Widget _row(IconData ic, String s) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 2),
    child: Row(children: [
      Icon(ic, size: 14, color: redotMuted),
      const SizedBox(width: 6),
      Expanded(child: Text(s, style: const TextStyle(color: redotMuted, fontSize: 13))),
    ]),
  );
}
