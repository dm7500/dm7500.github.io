---
layout: collection
title: "OSCP Prep"
permalink: "/oscp-prep/"
---

{% for page in site.oscp-prep %}

<a href="{{ page.url }}">
  {{page.title}}
  <H5>{{page.headline}}</H5>
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