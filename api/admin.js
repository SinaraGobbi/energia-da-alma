const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ erro: 'Método inválido' });
  const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  try {
    const jwt = (req.headers.authorization || '').replace('Bearer ', '');
    const { data: { user } } = await sb.auth.getUser(jwt);
    if (!user) return res.status(401).json({ erro: 'Sessão inválida. Entre de novo.' });
    const { data: adm } = await sb.from('admins').select('user_id').eq('user_id', user.id).maybeSingle();
    if (!adm) return res.status(403).json({ erro: 'Sem permissão.' });

    const b = req.body || {};
    const { data: { users } } = await sb.auth.admin.listUsers({ perPage: 1000 });

    if (b.acao === 'listar') {
      const { data: ac } = await sb.from('acessos').select('id,aluno_id,plano,expira_em,produtos(nome)');
      return res.json({ alunos: users.map(u => ({ id: u.id, email: u.email, acessos: (ac || []).filter(a => a.aluno_id === u.id) })) });
    }

    if (b.acao === 'liberar') {
      const email = (b.email || '').trim().toLowerCase();
      const meses = { mensal: 1, semestral: 6 }[b.plano];
      if (!email || !meses || !b.produto_id) return res.status(400).json({ erro: 'Preencha e-mail, produto e plano.' });
      let u = users.find(x => (x.email || '').toLowerCase() === email);
      if (!u) {
        if (!b.senha || b.senha.length < 6) return res.status(400).json({ erro: 'Aluno novo: informe uma senha de pelo menos 6 caracteres.' });
        const r = await sb.auth.admin.createUser({ email, password: b.senha, email_confirm: true });
        if (r.error) throw r.error;
        u = r.data.user;
      }
      const { data: ex } = await sb.from('acessos').select('*').eq('aluno_id', u.id).eq('produto_id', b.produto_id).maybeSingle();
      const base = ex && new Date(ex.expira_em) > new Date() ? new Date(ex.expira_em) : new Date();
      base.setMonth(base.getMonth() + meses);
      const dados = { plano: b.plano, expira_em: base.toISOString() };
      const q = ex ? sb.from('acessos').update(dados).eq('id', ex.id)
                   : sb.from('acessos').insert({ ...dados, aluno_id: u.id, produto_id: b.produto_id });
      const { error } = await q;
      if (error) throw error;
      return res.json({ ok: true, expira_em: dados.expira_em });
    }

    if (b.acao === 'revogar') {
      const { error } = await sb.from('acessos').update({ expira_em: new Date().toISOString() }).eq('id', b.acesso_id);
      if (error) throw error;
      return res.json({ ok: true });
    }

    return res.status(400).json({ erro: 'Ação desconhecida.' });
  } catch (e) {
    return res.status(500).json({ erro: e.message || 'Erro inesperado.' });
  }
};
