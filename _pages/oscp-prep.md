---
layout: collection
title: "OSCP Prep"
permalink: "/oscp-prep/"
---

{% for page in site.oscp-prep %}

<a href="{{ page.url }}">
  <H2>{{page.title}}</H2><br>
  <img src="{{page.picture}}"><br>
  <H4>{{page.headline}}</H4>
</a>


{% endfor %} 

<!-- <ul>
  {% for page in site.oscp-prep %}
    <li>
      <a href="{{ page.url }}">{{ page.title }}</a>
      - {{ page.headline }}
    </li>
  {% endfor %}
</ul> -->