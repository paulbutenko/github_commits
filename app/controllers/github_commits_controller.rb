class GithubCommitsController < ApplicationController

  unloadable

  skip_before_action :check_if_login_required
  skip_before_action :verify_authenticity_token

  before_action :verify_signature?

  GITHUB_URL = "https://github.com/"
  REDMINE_JOURNALIZED_TYPE = "Issue"
  REDMINE_ISSUE_NUMBER_PREFIX = "#rm"

  def create_comment
    resp_json = nil
    if params[:commits].present?

      repository_name = params[:repository][:name]
      branch = params[:ref].split("/").last

      params[:commits].each do |last_commit|
        message = last_commit[:message]

        if message.present? && is_commit_to_be_tracked?(last_commit)
          issue_id = message.partition(REDMINE_ISSUE_NUMBER_PREFIX).last.split(" ").first.to_i
          issue = Issue.find_by(id: issue_id)
        end

        if last_commit.present? && issue.present?

          email = EmailAddress.find_by(address: last_commit[:author][:email])
          user = email.present? ? email.user : User.where(admin: true).first

          author = last_commit[:author][:name]

          notes = t('commit.message', author: author,
                                      branch: branch,
                                      message: message,
                                      commit_id: last_commit[:id],
                                      commit_url: last_commit[:url])

          issue.journals.create(journalized_id: issue_id,
                                journalized_type: REDMINE_JOURNALIZED_TYPE,
                                user: user,
                                notes: notes
                               )
          resp_json = {success: true}
        else
          resp_json = {success: false, error: t('lables.no_issue_found') }
        end
      end
    elsif params[:pull_request].present?
      pr_number = params[:pull_request][:number]
      pr_state  = params[:pull_request][:state]
      pr_url    = params[:pull_request][:html_url]
      author    = params[:pull_request][:user][:login]
      message   = params[:pull_request][:title]

      if message.present? && message.include?(REDMINE_ISSUE_NUMBER_PREFIX)
        issue_id = message.partition(REDMINE_ISSUE_NUMBER_PREFIX).last.split(" ").first.to_i
        issue    = Issue.find_by(id: issue_id)
      end

      if issue.present?
        user = User.where(admin: true).first
        notes = t('pull_request.message',
                  author:    author,
                  message:   message,
                  pr_number: pr_number,
                  pr_state:  pr_state,
                  pr_url:    pr_url)
        issue.journals.create(journalized_id:   issue_id,
                              journalized_type: REDMINE_JOURNALIZED_TYPE,
                              user:             user,
                              notes:            notes
        )
        resp_json = { success: true }
      else
        resp_json = { success: false, error: t('lables.no_issue_found') }
      end
    else
      resp_json = {success: false, error: t('lables.no_commit_data_found') }
    end

    respond_to do |format|
      format.json { render json: resp_json, status: :ok }
    end

  end

  def verify_signature?
    if request.env['HTTP_X_HUB_SIGNATURE'].blank? || ENV["GITHUB_SECRET_TOKEN"].blank?
      render json: {success: false},status: 500
    else
      request.body.rewind
      payload_body = request.body.read
      signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), ENV["GITHUB_SECRET_TOKEN"], payload_body)
      render json: {success: false},status: 500 unless Rack::Utils.secure_compare(signature, request.env['HTTP_X_HUB_SIGNATURE'])
    end
  end

  private

  def is_commit_to_be_tracked?(commit_obj)
    commit_obj[:distinct] == true &&  #is it a fresh commit ?
    commit_obj[:message].include?(REDMINE_ISSUE_NUMBER_PREFIX) #Does it include the redmine issue prefix string pattern?
  end
end
