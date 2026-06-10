import 'package:flutter/material.dart';

import '../api.dart';
import '../models.dart';
import '../theme.dart';
import '../widgets/ticket_row.dart';
import 'ticket_detail.dart';

class TicketsListScreen extends StatefulWidget {
  const TicketsListScreen({super.key});
  @override
  State<TicketsListScreen> createState() => _TicketsListScreenState();
}

class _TicketsListScreenState extends State<TicketsListScreen> {
  Future<List<Ticket>>? _future;
  String? _statusFilter;
  String? _priorityFilter;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    setState(() {
      _future = Api.instance.tickets(status: _statusFilter, priority: _priorityFilter);
    });
    await _future;
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
        child: Row(children: [
          const Text('Tickets', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w700)),
          const Spacer(),
          PopupMenuButton<String>(
            tooltip: 'Filter',
            icon: const Icon(Icons.filter_list),
            onSelected: (v) {
              setState(() {
                if (v.startsWith('s:')) _statusFilter = v == 's:all' ? null : v.substring(2);
                if (v.startsWith('p:')) _priorityFilter = v == 'p:all' ? null : v.substring(2);
              });
              _reload();
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 's:all', child: Text('All statuses')),
              PopupMenuItem(value: 's:open', child: Text('Open')),
              PopupMenuItem(value: 's:in_progress', child: Text('In progress')),
              PopupMenuItem(value: 's:resolved', child: Text('Resolved')),
              PopupMenuDivider(),
              PopupMenuItem(value: 'p:all', child: Text('All priorities')),
              PopupMenuItem(value: 'p:p1', child: Text('P1 only')),
              PopupMenuItem(value: 'p:p2', child: Text('P2 only')),
              PopupMenuItem(value: 'p:p3', child: Text('P3 only')),
            ],
          ),
        ]),
      ),
      if (_statusFilter != null || _priorityFilter != null)
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
          child: Wrap(spacing: 8, children: [
            if (_statusFilter != null)
              Chip(
                label: Text(_statusFilter!),
                onDeleted: () { setState(() => _statusFilter = null); _reload(); },
              ),
            if (_priorityFilter != null)
              Chip(
                label: Text(_priorityFilter!.toUpperCase()),
                backgroundColor: priorityColor(_priorityFilter!).withOpacity(0.12),
                onDeleted: () { setState(() => _priorityFilter = null); _reload(); },
              ),
          ]),
        ),
      Expanded(
        child: RefreshIndicator(
          color: redotRed,
          onRefresh: _reload,
          child: FutureBuilder<List<Ticket>>(
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
                      Text(snap.error.toString(), textAlign: TextAlign.center, style: const TextStyle(color: redotMuted)),
                      const SizedBox(height: 12),
                      TextButton(onPressed: _reload, child: const Text('Retry')),
                    ]),
                  ),
                ]);
              }
              final tickets = snap.data ?? [];
              if (tickets.isEmpty) {
                return ListView(children: const [
                  Padding(
                    padding: EdgeInsets.all(40),
                    child: Column(children: [
                      Icon(Icons.check_circle_outline, size: 48, color: redotMuted),
                      SizedBox(height: 12),
                      Text('No tickets match this filter', style: TextStyle(color: redotMuted)),
                    ]),
                  ),
                ]);
              }
              return ListView.separated(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                itemCount: tickets.length,
                separatorBuilder: (_, __) => const SizedBox(height: 8),
                itemBuilder: (_, i) => TicketRow(
                  ticket: tickets[i],
                  onTap: () async {
                    await Navigator.of(context).push(MaterialPageRoute(
                      builder: (_) => TicketDetailScreen(ticketId: tickets[i].id),
                    ));
                    _reload();
                  },
                ),
              );
            },
          ),
        ),
      ),
    ]);
  }
}
