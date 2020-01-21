---
layout: collection
title: "OSCPPrep"
permalink: "/oscp-prep/"
---

<ul>
  {% for page in site.oscp-prep %}
    <li>
      <a href="{{ page.url }}">{{ page.title }}</a>
      - {{ page.headline }}
    </li>
  {% endfor %}
</ul>