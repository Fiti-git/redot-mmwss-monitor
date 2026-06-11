import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../api.dart';
import '../models.dart';
import '../theme.dart';
import '../auth_store.dart';
import '../widgets/kpi_card.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  Future<DashboardData>? _future;
  String? _name;

  @override
  void initState() {
    super.initState();
    _reload();
    AuthStore.instance.readUser().then((u) {
      if (mounted) setState(() => _name = u['name']);
    });
  }

  Future<void> _reload() async {
    setState(() { _future = Api.instance.dashboard(); });
    await _future;
  }

  @override
  Widget build(BuildContext context) {
    return RefreshIndicator(
      color: redotRed,
      onRefresh: _reload,
      child: SingleChildScrollView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 28),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (_name != null)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 4, horizontal: 4),
                child: Text('Hello, ${_name!.split(' ').first}',
                    style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w600,
                        color: redotMuted)),
              ),
            const SizedBox(height: 8),
            FutureBuilder<DashboardData>(
              future: _future,
              builder: (ctx, snap) {
                if (snap.connectionState == ConnectionState.waiting) {
                  return const Padding(
                    padding: EdgeInsets.symmetric(vertical: 80),
                    child: Center(child: CircularProgressIndicator(color: redotRed)),
                  );
                }
                if (snap.hasError) return _ErrorBox(error: snap.error!, onRetry: _reload);
                final d = snap.data!;
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _section('Overview'),
                    Wrap(spacing: 12, runSpacing: 12, children: [
                      KpiCard(label: 'Sites', value: '${d.stats.zones}', icon: Icons.public, color: const Color(0xFF3B82F6)),
                      KpiCard(label: 'Open incidents', value: '${d.stats.openIncidents}', icon: Icons.warning_amber, color: const Color(0xFFF59E0B)),
                      KpiCard(label: 'Requests 24h', value: _compact(d.stats.requests24h), icon: Icons.swap_horiz, color: const Color(0xFF10B981)),
                      KpiCard(label: 'Threats 24h', value: _compact(d.stats.threats24h), icon: Icons.shield, color: redotRed),
                      KpiCard(label: 'Cache hit', value: '${d.stats.hitRatio.toStringAsFixed(1)}%', icon: Icons.bolt, color: const Color(0xFF8B5CF6)),
                      KpiCard(label: 'Uptime 24h',
                          value: '${((d.uptime24h['percent'] ?? 100) as num).toStringAsFixed(2)}%',
                          icon: Icons.check_circle, color: const Color(0xFF10B981)),
                    ]),
                    const SizedBox(height: 20),
                    _section('Tickets'),
                    Row(children: [
                      Expanded(child: KpiCard(label: 'Open', value: '${d.tickets.openTotal}', icon: Icons.inbox, color: redotInk)),
                      const SizedBox(width: 12),
                      Expanded(child: KpiCard(label: 'P1', value: '${d.tickets.byPriority['p1'] ?? 0}', icon: Icons.priority_high, color: priorityColor('p1'))),
                    ]),
                    const SizedBox(height: 12),
                    Row(children: [
                      Expanded(child: KpiCard(label: 'P2', value: '${d.tickets.byPriority['p2'] ?? 0}', icon: Icons.flag, color: priorityColor('p2'))),
                      const SizedBox(width: 12),
                      Expanded(child: KpiCard(label: 'P3+P4', value: '${(d.tickets.byPriority['p3'] ?? 0) + (d.tickets.byPriority['p4'] ?? 0)}', icon: Icons.flag_outlined, color: priorityColor('p3'))),
                    ]),
                    const SizedBox(height: 20),
                    _section('Security score'),
                    Container(
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(
                        color: Colors.white, borderRadius: BorderRadius.circular(12),
                      ),
                      child: Row(
                        children: [
                          Text('${d.security['score'] ?? '—'}',
                              style: const TextStyle(fontSize: 36, fontWeight: FontWeight.w800, color: redotInk)),
                          const SizedBox(width: 16),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                _scoreRow('Critical', d.security['rec_critical'] ?? 0, redotRed),
                                _scoreRow('Warning',  d.security['rec_warning']  ?? 0, const Color(0xFFF59E0B)),
                                _scoreRow('Info',     d.security['rec_info']     ?? 0, const Color(0xFF3B82F6)),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 24),
                    Center(
                      child: Text('Pulled ${DateFormat('HH:mm:ss').format(DateTime.now())}',
                          style: const TextStyle(color: redotMuted, fontSize: 11)),
                    ),
                  ],
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _section(String label) => Padding(
    padding: const EdgeInsets.fromLTRB(4, 16, 4, 8),
    child: Text(label.toUpperCase(),
        style: const TextStyle(letterSpacing: 1.2, fontSize: 11,
            fontWeight: FontWeight.w700, color: redotMuted)),
  );

  Widget _scoreRow(String label, dynamic count, Color color) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 1),
    child: Row(children: [
      Container(width: 8, height: 8, decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
      const SizedBox(width: 8),
      Text(label, style: const TextStyle(color: redotMuted)),
      const Spacer(),
      Text('$count', style: const TextStyle(fontWeight: FontWeight.w600)),
    ]),
  );

  String _compact(int n) {
    if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(1)}K';
    return '$n';
  }
}

class _ErrorBox extends StatelessWidget {
  final Object error;
  final VoidCallback onRetry;
  const _ErrorBox({required this.error, required this.onRetry});
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 40),
      child: Column(children: [
        const Icon(Icons.cloud_off, size: 48, color: redotMuted),
        const SizedBox(height: 12),
        Text(error.toString(), textAlign: TextAlign.center,
            style: const TextStyle(color: redotMuted)),
        const SizedBox(height: 12),
        TextButton(onPressed: onRetry, child: const Text('Retry')),
      ]),
    );
  }
}
