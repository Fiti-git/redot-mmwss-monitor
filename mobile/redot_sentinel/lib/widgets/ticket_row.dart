import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../models.dart';
import '../theme.dart';

class TicketRow extends StatelessWidget {
  final Ticket ticket;
  final VoidCallback onTap;
  const TicketRow({super.key, required this.ticket, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final pc = priorityColor(ticket.priority);
    return Material(
      color: Colors.white,
      borderRadius: BorderRadius.circular(12),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 4, height: 56,
                decoration: BoxDecoration(
                  color: pc, borderRadius: BorderRadius.circular(2),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                      decoration: BoxDecoration(
                        color: pc.withOpacity(0.12),
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: Text(ticket.priority.toUpperCase(),
                          style: TextStyle(color: pc, fontWeight: FontWeight.w700, fontSize: 11)),
                    ),
                    const SizedBox(width: 6),
                    Text('#${ticket.id}',
                        style: const TextStyle(color: redotMuted, fontSize: 12)),
                    const SizedBox(width: 6),
                    if (ticket.zoneName != null) Expanded(
                      child: Text(ticket.zoneName!,
                          maxLines: 1, overflow: TextOverflow.ellipsis,
                          style: const TextStyle(color: redotMuted, fontSize: 12)),
                    ),
                  ]),
                  const SizedBox(height: 4),
                  Text(ticket.title,
                      maxLines: 2, overflow: TextOverflow.ellipsis,
                      style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
                  const SizedBox(height: 6),
                  Row(children: [
                    _slaDot(ticket.sla.responseState, 'R'),
                    const SizedBox(width: 6),
                    _slaDot(ticket.sla.resolutionState, 'X'),
                    const SizedBox(width: 8),
                    Text(_when(ticket.openedAt),
                        style: const TextStyle(color: redotMuted, fontSize: 11)),
                    const Spacer(),
                    Text(ticket.status,
                        style: const TextStyle(color: redotMuted, fontSize: 11)),
                  ]),
                ]),
              ),
              const Icon(Icons.chevron_right, color: redotMuted),
            ],
          ),
        ),
      ),
    );
  }

  Widget _slaDot(String state, String letter) {
    final c = slaColor(state);
    return Container(
      width: 14, height: 14,
      alignment: Alignment.center,
      decoration: BoxDecoration(color: c.withOpacity(0.15), shape: BoxShape.circle),
      child: Text(letter, style: TextStyle(color: c, fontSize: 8, fontWeight: FontWeight.w800)),
    );
  }

  String _when(DateTime opened) {
    final diff = DateTime.now().difference(opened);
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return DateFormat('MMM d').format(opened.toLocal());
  }
}
