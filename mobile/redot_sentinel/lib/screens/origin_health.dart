import 'package:flutter/material.dart';

import '../api.dart';
import '../models.dart';
import '../theme.dart';

class OriginHealthScreen extends StatefulWidget {
  const OriginHealthScreen({super.key});
  @override
  State<OriginHealthScreen> createState() => _OriginHealthScreenState();
}

class _OriginHealthScreenState extends State<OriginHealthScreen> {
  Future<List<OriginHealthZone>>? _future;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    setState(() => _future = Api.instance.originHealth());
    await _future;
  }

  Color _uptimeColor(double? pct) {
    if (pct == null) return redotMuted;
    if (pct >= 99.9) return const Color(0xFF10B981);
    if (pct >= 99.0) return const Color(0xFFF59E0B);
    return redotRed;
  }

  Color _awsStateColor(String? s) {
    if (s == 'running') return const Color(0xFF10B981);
    if (s == 'stopped') return redotRed;
    return const Color(0xFFF59E0B);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Origin health')),
      body: RefreshIndicator(
        color: redotRed,
        onRefresh: _reload,
        child: FutureBuilder<List<OriginHealthZone>>(
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
            final zones = snap.data ?? [];
            return ListView(
              padding: const EdgeInsets.all(16),
              children: [
                for (final z in zones) _zoneCard(z),
                const SizedBox(height: 24),
                const Center(child: Text('Uptime probe runs every 60 s.',
                    style: TextStyle(color: redotMuted, fontSize: 11))),
              ],
            );
          },
        ),
      ),
    );
  }

  Widget _zoneCard(OriginHealthZone z) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Expanded(
              child: Text(z.zoneName,
                  style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
            ),
            if (z.latestOk != null)
              Icon(
                z.latestOk! ? Icons.check_circle : Icons.error,
                color: z.latestOk! ? const Color(0xFF10B981) : redotRed,
                size: 20,
              ),
          ]),
          const SizedBox(height: 12),

          // Uptime 24h
          Row(children: [
            _stat('Uptime 24h',
                z.uptimePct24h != null ? '${z.uptimePct24h!.toStringAsFixed(2)}%' : '—',
                color: _uptimeColor(z.uptimePct24h)),
            const SizedBox(width: 12),
            _stat('Avg latency',
                z.avgLatencyMs != null ? '${z.avgLatencyMs!.toStringAsFixed(0)} ms' : '—'),
            const SizedBox(width: 12),
            _stat('Checks', '${z.checks24h}'),
          ]),

          if (z.aws['instance'] != null) ...[
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: const Color(0xFFF7F7F8),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  const Icon(Icons.dns, size: 14, color: redotMuted),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text('${z.aws['instance']} · ${z.aws['bundle'] ?? "?"} · ${z.aws['ram_gb'] ?? "?"} GB RAM',
                        style: const TextStyle(fontSize: 12, color: redotInk, fontWeight: FontWeight.w600)),
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: _awsStateColor(z.aws['state']).withOpacity(0.15),
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Text('${z.aws['state'] ?? '?'}',
                        style: TextStyle(
                            color: _awsStateColor(z.aws['state']),
                            fontSize: 10, fontWeight: FontWeight.w700)),
                  ),
                ]),
                const SizedBox(height: 8),
                Row(children: [
                  if (z.aws['cpu_avg'] != null)
                    _miniStat('CPU avg', '${(z.aws['cpu_avg'] as num).toStringAsFixed(1)}%'),
                  if (z.aws['cpu_max'] != null) ...[
                    const SizedBox(width: 12),
                    _miniStat('CPU max', '${(z.aws['cpu_max'] as num).toStringAsFixed(1)}%'),
                  ],
                  if (z.aws['burst_pct'] != null) ...[
                    const SizedBox(width: 12),
                    _miniStat('Burst', '${(z.aws['burst_pct'] as num).toStringAsFixed(0)}%'),
                  ],
                ]),
                if (z.aws['status_failed'] == true) ...[
                  const SizedBox(height: 6),
                  const Row(children: [
                    Icon(Icons.warning_amber, color: redotRed, size: 14),
                    SizedBox(width: 4),
                    Text('AWS status check failed',
                        style: TextStyle(color: redotRed, fontSize: 12, fontWeight: FontWeight.w600)),
                  ]),
                ],
              ]),
            ),
          ],
        ]),
      ),
    );
  }

  Widget _stat(String label, String value, {Color? color}) => Expanded(
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(value, style: TextStyle(
          fontSize: 18, fontWeight: FontWeight.w800, color: color ?? redotInk)),
      const SizedBox(height: 2),
      Text(label, style: const TextStyle(fontSize: 11, color: redotMuted)),
    ]),
  );

  Widget _miniStat(String label, String value) => Row(children: [
    Text('$label ', style: const TextStyle(fontSize: 11, color: redotMuted)),
    Text(value, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: redotInk)),
  ]);
}
