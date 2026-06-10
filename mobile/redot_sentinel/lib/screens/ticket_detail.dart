import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../api.dart';
import '../models.dart';
import '../theme.dart';

class TicketDetailScreen extends StatefulWidget {
  final int ticketId;
  const TicketDetailScreen({super.key, required this.ticketId});
  @override
  State<TicketDetailScreen> createState() => _TicketDetailScreenState();
}

class _TicketDetailScreenState extends State<TicketDetailScreen> {
  Future<TicketDetail>? _future;
  final _comment = TextEditingController();
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  @override
  void dispose() {
    _comment.dispose();
    super.dispose();
  }

  Future<void> _reload() async {
    setState(() => _future = Api.instance.ticket(widget.ticketId));
    await _future;
  }

  Future<void> _respond() async {
    setState(() => _busy = true);
    try {
      await Api.instance.ticketRespond(widget.ticketId, null);
      await _reload();
    } on ApiError catch (e) {
      _snack(e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _sendComment() async {
    final body = _comment.text.trim();
    if (body.isEmpty) return;
    setState(() => _busy = true);
    try {
      await Api.instance.ticketComment(widget.ticketId, body);
      _comment.clear();
      await _reload();
    } on ApiError catch (e) {
      _snack(e.message);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _snack(String m) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(m)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Ticket #${widget.ticketId}')),
      body: FutureBuilder<TicketDetail>(
        future: _future,
        builder: (ctx, snap) {
          if (snap.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator(color: redotRed));
          }
          if (snap.hasError) {
            return Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(snap.error.toString(), style: const TextStyle(color: redotMuted)),
              ),
            );
          }
          final d = snap.data!;
          final t = d.ticket;
          final dt = DateFormat('yyyy-MM-dd HH:mm');

          return RefreshIndicator(
            color: redotRed,
            onRefresh: _reload,
            child: ListView(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
              children: [
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Row(children: [
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                          decoration: BoxDecoration(
                            color: priorityColor(t.priority).withOpacity(0.12),
                            borderRadius: BorderRadius.circular(20),
                          ),
                          child: Text(t.priority.toUpperCase(),
                              style: TextStyle(color: priorityColor(t.priority),
                                  fontWeight: FontWeight.w700)),
                        ),
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                          decoration: BoxDecoration(
                            color: const Color(0xFFE5E7EB),
                            borderRadius: BorderRadius.circular(20),
                          ),
                          child: Text(t.status,
                              style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 12)),
                        ),
                      ]),
                      const SizedBox(height: 12),
                      Text(t.title, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
                      const SizedBox(height: 8),
                      if (t.zoneName != null) ...[
                        _meta(Icons.public, t.zoneName!),
                        const SizedBox(height: 4),
                      ],
                      _meta(Icons.schedule, 'Opened ${dt.format(t.openedAt.toLocal())}'),
                      if (t.responseAt != null) ...[
                        const SizedBox(height: 4),
                        _meta(Icons.reply, 'Responded ${dt.format(t.responseAt!.toLocal())}'),
                      ],
                      if (t.resolvedAt != null) ...[
                        const SizedBox(height: 4),
                        _meta(Icons.check_circle_outline, 'Resolved ${dt.format(t.resolvedAt!.toLocal())}'),
                      ],
                      const SizedBox(height: 12),
                      Row(children: [
                        _slaPill('Response', t.sla.responseState),
                        const SizedBox(width: 8),
                        _slaPill('Resolution', t.sla.resolutionState),
                      ]),
                    ]),
                  ),
                ),
                if (d.description != null && d.description!.isNotEmpty) ...[
                  const SizedBox(height: 8),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        const Text('Description', style: TextStyle(
                            fontSize: 11, letterSpacing: 1.2, color: redotMuted,
                            fontWeight: FontWeight.w700)),
                        const SizedBox(height: 8),
                        Text(d.description!),
                      ]),
                    ),
                  ),
                ],
                if (d.resolutionNotes != null && d.resolutionNotes!.isNotEmpty) ...[
                  const SizedBox(height: 8),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        const Text('Resolution', style: TextStyle(
                            fontSize: 11, letterSpacing: 1.2, color: redotMuted,
                            fontWeight: FontWeight.w700)),
                        const SizedBox(height: 8),
                        Text(d.resolutionNotes!),
                      ]),
                    ),
                  ),
                ],
                const SizedBox(height: 16),
                if (t.responseAt == null)
                  ElevatedButton.icon(
                    onPressed: _busy ? null : _respond,
                    icon: const Icon(Icons.reply),
                    label: const Text('Acknowledge response'),
                  ),
                const SizedBox(height: 16),
                const Text('TIMELINE', style: TextStyle(
                    fontSize: 11, letterSpacing: 1.2, color: redotMuted,
                    fontWeight: FontWeight.w700)),
                const SizedBox(height: 8),
                for (final e in d.events) _eventRow(e, dt),
                const SizedBox(height: 16),
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: Column(children: [
                      TextField(
                        controller: _comment,
                        decoration: const InputDecoration(
                          hintText: 'Add a comment…',
                          border: InputBorder.none,
                        ),
                        maxLines: 3,
                      ),
                      Row(mainAxisAlignment: MainAxisAlignment.end, children: [
                        TextButton.icon(
                          onPressed: _busy ? null : _sendComment,
                          icon: const Icon(Icons.send),
                          label: const Text('Comment'),
                        ),
                      ]),
                    ]),
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  Widget _meta(IconData ic, String s) => Row(children: [
    Icon(ic, size: 14, color: redotMuted),
    const SizedBox(width: 6),
    Expanded(child: Text(s, style: const TextStyle(color: redotMuted, fontSize: 13))),
  ]);

  Widget _slaPill(String label, String state) {
    final c = slaColor(state);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: c.withOpacity(0.12),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text('$label: $state',
          style: TextStyle(color: c, fontWeight: FontWeight.w600, fontSize: 12)),
    );
  }

  Widget _eventRow(TicketEvent e, DateFormat dt) {
    String body = e.eventType;
    if (e.details != null) {
      if (e.details!['body'] != null) body = e.details!['body'].toString();
      else if (e.details!['note'] != null) body = e.details!['note'].toString();
    }
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Container(width: 8, height: 8, margin: const EdgeInsets.only(top: 6),
            decoration: const BoxDecoration(color: redotRed, shape: BoxShape.circle)),
        const SizedBox(width: 10),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(e.eventType, style: const TextStyle(fontWeight: FontWeight.w600)),
            if (body != e.eventType) Padding(
              padding: const EdgeInsets.only(top: 2),
              child: Text(body, style: const TextStyle(color: redotInk)),
            ),
            Text('${e.userEmail ?? 'system'} · ${dt.format(e.ts.toLocal())}',
                style: const TextStyle(color: redotMuted, fontSize: 11)),
          ]),
        ),
      ]),
    );
  }
}
