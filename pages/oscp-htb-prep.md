---
layout: page
title: "OSCP/HTB Prep Walk-Throughs"
permalink: "/oscp-htb-prep/"
---

<ul>
  {% for page in site.oscp-htb-prep %}
    <li>
      <a href="{{ page.url }}">{{ page.title }}</a>
      - {{ page.headline }}
    </li>
  {% endfor %}
</ul>