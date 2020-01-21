---
layout: collection
title: "OSCP Prep"
permalink: "/oscp-prep/"
---

{% for page in site.oscp-prep %}

<a href="{{ page.url }}">
  <h2>{{page.title}}</h2>
  <H4>{{page.headline}}</H4>
  <img src="{{page.picture}}"><br>
  <hr>


{% endfor %} 

<!-- <ul>
  {% for page in site.oscp-prep %}
    <li>
      <a href="{{ page.url }}">{{ page.title }}</a>
      - {{ page.headline }}
    </li>
  {% endfor %}
</ul> -->