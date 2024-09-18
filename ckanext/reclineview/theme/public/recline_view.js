this.ckan.module('recline_view', function (jQuery) {
  return {
    options: {
      site_url: "",
      controlsClassName: "controls",
      dataproxyUrl: "//jsonpdataproxy.appspot.com"
    },

    initialize: function () {
      jQuery.proxyAll(this, /_on/);
      this.options.resource = JSON.parse(this.options.resource);
      this.options.resourceView = JSON.parse(this.options.resourceView);
      this.el.ready(this._onReady);
    },

    _onReady: function() {
      var resourceData = this.options.resource,
          resourceView = this.options.resourceView;

      this.loadView(resourceData, resourceView);
    },

    loadView: function (resourceData, reclineView) {
      var self = this;

      function showError(msg){
        msg = msg || self._('error loading view');
        window.parent.ckan.pubsub.publish('data-viewer-error', msg);
      }

      if (resourceData.formatNormalized === '') {
        var tmp = resourceData.url.split('/');
        tmp = tmp[tmp.length - 1];
        tmp = tmp.split('?'); // query strings
        tmp = tmp[0];
        var ext = tmp.split('.');
        if (ext.length > 1) {
          resourceData.formatNormalized = ext[ext.length-1];
        }
      }

      var errorMsg, dataset;

      if (!resourceData.datastore_active) {
          recline.Backend.DataProxy.timeout = 10000;

          recline.Backend.DataProxy.dataproxy_url = this.options.dataproxyUrl;

          resourceData.backend =  'dataproxy';
      } else {
          resourceData.backend =  'ckan';
          resourceData.endpoint = jQuery('body').data('site-root') + 'api';
      }

      dataset = new recline.Model.Dataset(resourceData);

      var query = new recline.Model.Query();
      query.set({ size: reclineView.limit || 100 });
      query.set({ from: reclineView.offset || 0 });

      var urlFilters = {};
      try {
        if (window.parent.ckan.views && window.parent.ckan.views.filters) {
          urlFilters = window.parent.ckan.views.filters.get();
        }
      } catch(e) {}
      var defaultFilters = reclineView.filters || {},
          filters = jQuery.extend({}, defaultFilters, urlFilters);
      jQuery.each(filters, function (field,values) {
        query.addFilter({type: 'term', field: field, term: values});
      });

      dataset.queryState.set(query.toJSON(), {silent: true});

      errorMsg = this._('Could not load view') + ': ';
      if (resourceData.backend == 'ckan') {
        errorMsg += this._('DataStore returned an error');
      } else if (resourceData.backend == 'dataproxy'){
        errorMsg += this._('DataProxy returned an error');
      }
      dataset.fetch()
        .done(function(dataset){
            self.initializeView(dataset, reclineView);
        })
        .fail(function(error){
          if (error.message) errorMsg += ' (' + error.message + ')';
          showError(errorMsg);
        });
    },

    initializeView: function (dataset, reclineView) {
      var view,
          state,
          controls = [];

      if(reclineView.view_type === "recline_graph_view") {
        state = {
          "graphType": reclineView.graph_type,
          "group": reclineView.group,
          "series": [reclineView.series]
        };
        view = new recline.View.Graph({model: dataset, state: state});
      }else if(reclineView.view_type === "recline_view") {
        view = this._newDataExplorer(dataset);
      } else {
        // default to Grid
        view = new recline.View.SlickGrid({model: dataset});
        controls = [
          new recline.View.Pager({model: view.model}),
          new recline.View.RecordCount({model: dataset}),
          new recline.View.QueryEditor({model: view.model.queryState})
        ];
      }

      // recline_view automatically adds itself to the DOM, so we don't
      // need to bother with it.
      if(reclineView.view_type !== 'recline_view') {
        var newElements = jQuery('<div />');
        this._renderControls(newElements, controls, this.options.controlsClassName);
        newElements.append(view.el);
        jQuery(this.el).html(newElements);
        view.visible = true;
        view.render();
      }

      if(reclineView.view_type === "recline_graph_view") {
        view.redraw();
      }
    },

    _newDataExplorer: function (dataset) {
      var views = [
        {
          id: 'grid',
          label: this._('Grid'),
          view: new recline.View.SlickGrid({
            model: dataset
          })
        },
        {
          id: 'graph',
          label: this._('Graph'),
          view: new recline.View.Graph({
            model: dataset
          })
        },
      ];

      var sidebarViews = [
        {
          id: 'valueFilter',
          label: this._('Filters'),
          view: new recline.View.ValueFilter({
            model: dataset
          })
        }
      ];

      var dataExplorer = new recline.View.MultiView({
        el: this.el,
        model: dataset,
        views: views,
        sidebarViews: sidebarViews,
        config: {
          readOnly: true
        }
      });

      return dataExplorer;
    },

    _renderControls: function (el, controls, className) {
      var controlsEl = jQuery("<div class=\"clearfix " + className + "\" />");
      for (var i = 0; i < controls.length; i++) {
        controlsEl.append(controls[i].el);
      }
      jQuery(el).append(controlsEl);
    }
  };
});
